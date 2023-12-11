package main

import (
	"bytes"
	"context"
	"encoding/pem"
	"os"
	"reflect"
	"time"

	"github.com/jrhouston/k8slock"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"

	"github.com/urfave/cli/v2"
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
// certPath         = flag.String("cert-path", "/etc/neuvector/certs/internal/migration/", "The folder containing internal certs")
// subjectCN        = flag.String("subject", "NeuVector", "expected subject name from remote server")
// kubeconfig       = flag.String("kubeconfig", "", "Paths to a kubeconfig. Only required if out-of-cluster.")
// namespace        = flag.String("namespace", "neuvector", "Kubernetes namespace that NeuVector is running in.")
// timeout          = flag.Duration("timeout", 0, "timeout for waiting deployment to complete")
// grpcPort         = flag.Int("grpc-port", 18500, "the listening port for migration gRPC server")
// activeSecretName = flag.String("active-secret-name", "neuvector-internal-certs-active", "the active secret used by containers")
// dstSecretName    = flag.String("dest-secret-name", "neuvector-internal-certs-dest", "the secret location to be applied")
// newSecretName    = flag.String("new-secret-name", "neuvector-internal-certs", "the new secret to be applied")
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

// We should just verify its cert signer
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

// Check if a legacy internal cert is still being used.
// TODO: Only call this during pre-install hook.
// TODO: Consider argocd and operator-sdk
func containLegacyDefaultInternalCerts(client dynamic.Interface, namespace string) (bool, error) {
	item, err := client.Resource(
		schema.GroupVersionResource{
			Resource: "pods",
			Version:  "v1",
		},
	).Namespace(namespace).List(context.TODO(), metav1.ListOptions{
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

func CreateLocker(namespace string, holdername string) (*k8slock.Locker, error) {
	return k8slock.NewLocker(
		"internal-cert-migration-lock",
		k8slock.RetryWaitDuration(time.Second*30),
		k8slock.Namespace(namespace),
		k8slock.TTL(time.Hour*2),
		k8slock.ClientID(holdername),
	)
}

func main() {
	app := cli.NewApp()

	app.Flags = []cli.Flag{
		&cli.StringFlag{
			Name:  "kube-config",
			Value: "",
			Usage: "the active secret used by containers",
		},
		&cli.StringFlag{
			Name:  "namespace",
			Value: "neuvector",
			Usage: "The k8s namespace where NeuVector is running in",
		},
		&cli.StringFlag{
			Name:  "active-secret-name",
			Value: "neuvector-internal-certs-active",
			Usage: "the active secret used by containers",
		},
		&cli.StringFlag{
			Name:  "dest-secret-name",
			Value: "neuvector-internal-certs-dest",
			Usage: "the storage of internal certs",
		},
		&cli.StringFlag{
			Name:  "new-secret-name",
			Value: "neuvector-internal-certs",
			Usage: "the new secret to be applied",
		},
	}
	app.Commands = cli.Commands{
		&cli.Command{
			Name:  "pre-sync-hook",
			Usage: "Run neuvector pre sync hook",
			Flags: []cli.Flag{
				&cli.BoolFlag{
					Name:  "force-create-cert",
					Value: false,
					Usage: "Force to create new internal certificates",
				},
				&cli.BoolFlag{
					Name:  "user-managed-cert",
					Value: false,
					Usage: "Whether user manages on their own",
				},
				&cli.IntFlag{
					Name:  "rsa-key-length",
					Value: 4096,
					Usage: "RSA key length when creating new internal key and certificate",
				},
				&cli.DurationFlag{
					Name:  "expiry-cert-threshold",
					Value: 30 * 24 * time.Hour,
					Usage: "The threshold to automatically upgrade an internal cert",
				},
				&cli.IntFlag{
					Name:  "ca-cert-validity-days",
					Value: 365 * 5, // 5 years
					Usage: "The ca cert's validity period in days",
				},
				&cli.IntFlag{
					Name:  "cert-validity-days",
					Value: 365 * 2, // 2 years
					Usage: "The cert's validity period in days",
				},
			},
			Action: PreSyncHook,
		},
		&cli.Command{
			Name:  "post-sync-hook",
			Usage: "Run neuvector post sync hook",
			Flags: []cli.Flag{
				&cli.StringFlag{
					Name:  "migration-cert-path",
					Value: "/etc/neuvector/certs/internal/migration/",
					Usage: "The folder that contains migration certificates",
				},
				&cli.StringFlag{
					Name:  "certificate-cn",
					Value: "NeuVector",
					Usage: "The common field in internal certificate",
				},
				&cli.DurationFlag{
					Name:  "rollout-timeout",
					Value: 0,
					Usage: "The timeout for waiting deployment to complete",
				},
				&cli.IntFlag{
					Name:  "migration-grpc-port",
					Value: 18500,
					Usage: "The listening port for migration gRPC server",
				},
			},
			Action: PostSyncHook,
		},
	}

	if err := app.Run(os.Args); err != nil {
		log.WithError(err).Fatal("failed to run the command")
		os.Exit(1)
	}
	return
}
