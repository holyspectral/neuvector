package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"net"
	"os"
	"reflect"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

const (
	TARGET_SECRET_SOURCE_NAME_CACERT = "target-cacert"
	TARGET_SECRET_SOURCE_NAME_CERT   = "target-cert"
	TARGET_SECRET_SOURCE_NAME_KEY    = "target-key"

	// TODO: change file name to align with cert-manger default.
	CACERT_FILENAME = "ca.crt"
	CERT_FILENAME   = "tls.crt"
	KEY_FILENAME    = "tls.key"
)

// Go 1.14 + client-go  We had below options at design stage:
// 1. Use client-go + Go 1.16 => Need to patch build environment.
// 2. Use client-go + Go 1.14 => Works since we also include kubectl in this executable.
// 3. Use global.ORCH.StartWatchResource + Go 1.14 => should work too, but if we want cache support it will be getting complex.

var (
	certPath           = flag.String("cert-path", "/etc/neuvector/certs/internal/migration/", "The folder containing internal certs")
	subjectCN          = flag.String("subject", "NeuVector", "expected subject name from remote server")
	kubeconfig         = flag.String("kubeconfig", "", "Paths to a kubeconfig. Only required if out-of-cluster.")
	namespace          = flag.String("namespace", "neuvector", "Kubernetes namespace that NeuVector is running in.")
	timeout            = flag.Duration("timeout", 0, "timeout for waiting deployment to complete")
	grpcPort           = flag.Int("grpc-port", 18500, "the listening port for migration gRPC server")
	activeSecretName   = flag.String("active-secret-name", "neuvector-internal-certs-active", "the active secret used by containers")
	dstSecretName      = flag.String("dest-secret-name", "neuvector-internal-certs-dest", "the secret location to be applied")
	newSecretName      = flag.String("new-secret-name", "neuvector-internal-certs", "the new secret to be applied")
	forceUpdate        = flag.Bool("force-update", false, "force update internal certs by generating another one")
	rsaKeySize         = flag.Int("rsa-key-size", 4096, "rsa key size used in internal certs")
	mode               = flag.String("mode", "postsync-hook", "which mode to run")
	forceCreateNewCert = flag.Bool("force-new-cert", false, "whether to force create/update a new cert")
)

var (
	ControllerPodSelector = fields.OneTermEqualSelector("app", "neuvector-controller-pod").String()
	ScannerPodSelector    = fields.OneTermEqualSelector("app", "neuvector-scanner-pod").String()
	EnforcerPodSelector   = fields.OneTermEqualSelector("app", "neuvector-enforcer-pod").String()
)

var (
	ControllerConsulPort = "18300"
	ControllerGRPCPort   = "18400"
	EnforcerGRPCPort     = "18401"
	ScannerGRPCPort      = "18402"
)

func EqualInternalCerts(s1 *corev1.Secret, s2 *corev1.Secret) bool {
	if s1 == nil && s2 == nil {
		return true
	}
	if s1 == nil || s2 == nil {
		return false
	}
	return reflect.DeepEqual(s1.Data[CACERT_FILENAME], s2.Data[CACERT_FILENAME]) &&
		reflect.DeepEqual(s1.Data[CERT_FILENAME], s2.Data[CERT_FILENAME]) &&
		reflect.DeepEqual(s1.Data[KEY_FILENAME], s2.Data[KEY_FILENAME])
}

func GetRemoteCert(host string, port string) (*x509.Certificate, error) {
	conf := &tls.Config{
		InsecureSkipVerify: true,
	}

	addr := net.JoinHostPort(host, port)

	conn, err := tls.Dial("tcp", addr, conf)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to dial host: %s", host)
	}
	defer conn.Close()
	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return nil, errors.New("no remote certificate is available")
	}
	return certs[0], nil
}

// Check if a legacy internal cert is still being used.
// TODO: Only call this during pre-install hook.
// TODO: Consider argocd and operator-sdk
func containLegacyDefaultInternalCerts(client dynamic.Interface) (bool, error) {
	item, err := client.Resource(
		schema.GroupVersionResource{
			Resource: "pods",
			Version:  "v1",
		},
	).Namespace(*namespace).List(context.TODO(), metav1.ListOptions{
		LabelSelector: ControllerPodSelector,
	})
	if err != nil {
		return false, errors.Wrap(err, "failed to find controller pods")
	}

	var pods corev1.PodList
	err = runtime.DefaultUnstructuredConverter.
		FromUnstructured(item.UnstructuredContent(), &pods)
	if err != nil {
		return false, errors.Wrap(err, "failed to read pod list")
	}

	for _, pod := range pods.Items {
		log.WithFields(log.Fields{
			"pod": pod.Status.PodIP,
		}).Info("Getting gRPC and consul certs")

		cert, err := GetRemoteCert(pod.Status.PodIP, ControllerConsulPort)
		if err != nil {
			return false, errors.Wrapf(err, "failed to get remote certs from: %s", pod.Status.PodIP)
		}

		// Convert cert back to pem for comparison
		var b bytes.Buffer
		err = pem.Encode(&b, &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		})
		if err != nil {
			return false, errors.Wrapf(err, "failed to convert remote cert to PEM")
		}

		log.Infof("Issuer Name: %s\n", cert.Issuer)
		log.Infof("Expiry: %s \n", cert.NotAfter.Format("2006-January-02"))
		log.Infof("Common Name: %s \n", cert.Issuer.CommonName)
		if b.String() == LegacyCert {
			log.Info("Matched.")
			return true, nil
		}
	}
	return false, nil
}

func NewK8sClient(kubeconfig string) (dynamic.Interface, error) {
	var err error
	var config *rest.Config
	if len(kubeconfig) > 0 {
		config, err = clientcmd.BuildConfigFromFlags("", kubeconfig)
		if err != nil {
			return nil, errors.Wrap(err, "failed to build config from kubeconfig")
		}
	} else {
		config, err = rest.InClusterConfig()
		if err != nil {
			return nil, errors.Wrap(err, "failed to read in-cluster config")
		}
	}

	return dynamic.NewForConfig(config)
}

func main() {
	// TODO: Implement a lock, so only one instance will be running.  (Lease?)
	flag.Parse()

	var err error
	switch *mode {
	case "presync-hook":
		err = PreSyncHook()
	case "postsync-hook":
		err = PostSyncHook()
	default:
		flag.Usage()
		os.Exit(-1)
	}
	if err != nil {
		log.WithError(err).Fatal("failed to run")
	}
	return
}
