package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"io/ioutil"
	"net"
	"path"
	"reflect"
	"strconv"

	"github.com/neuvector/neuvector/share"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	appv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	k8sError "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/clientcmd"
	watchtools "k8s.io/client-go/tools/watch"
	"k8s.io/kubectl/pkg/polymorphichelpers"
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
	certPath         = flag.String("cert-path", "/etc/neuvector/certs/internal/migration/", "The folder containing internal certs")
	subjectCN        = flag.String("subject", "NeuVector", "expected subject name from remote server")
	kubeconfig       = flag.String("kubeconfig", "", "Paths to a kubeconfig. Only required if out-of-cluster.")
	namespace        = flag.String("namespace", "neuvector", "Kubernetes namespace that NeuVector is running in.")
	timeout          = flag.Duration("timeout", 0, "timeout for waiting deployment to complete")
	grpcPort         = flag.Int("grpc-port", 18500, "the listening port for migration gRPC server")
	activeSecretName = flag.String("active-secret-name", "neuvector-internal-certs-active", "the active secret")
	dstSecretName    = flag.String("target-secret-name", "neuvector-internal-certs-dest", "the existing secret that have been applied")
	srcSecretName    = flag.String("source-secret-name", "neuvector-internal-certs", "the new secret to be applied")
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

func main() {
	// TODO: Implement a lock, so only one instance will be running.  (Lease?)

	flag.Parse()
	var config *rest.Config
	var err error
	var secret *corev1.Secret

	if len(*kubeconfig) > 0 {
		config, err = clientcmd.BuildConfigFromFlags("", *kubeconfig)
		if err != nil {
			log.WithError(err).Panic("failed to build config from kubeconfig")
		}
	} else {
		config, err = rest.InClusterConfig()
		if err != nil {
			log.WithError(err).Fatal("failed to read in-cluster config")
		}
	}

	client, err := dynamic.NewForConfig(config)
	if err != nil {
		return
	}

	// 1. Wait until deployment completes
	ctx, cancel := watchtools.ContextWithOptionalTimeout(context.Background(), *timeout)
	defer cancel()
	err = WaitUntilRolledOut(ctx,
		schema.GroupVersionResource{Group: "apps", Version: "v1", Resource: "deployments"},
		"neuvector-controller-pod",
		client)

	// Flow:
	// src secret => target secret.  Eventually src and target will be the same.
	//
	// 0. When helm chart is installed, no secret will be created.
	// 		a. Retire cert-manager support?
	//		b. Or allow user/cert-manager to specify cert via src secret?
	//      c. Reconcile via controller? Or schedule job?
	// 1. When this job runs, it checks if either of below conditions is met.  If so, start migration.
	// 		a. cert is not present
	// 		b. a src secret is present
	// 2. Update target cert and call each component's reload.

	var srcSecret, dstSecret, activeSecret *corev1.Secret

	if dstSecret, err = GetK8sSecret(context.TODO(), client, *dstSecretName); err != nil {
		if !k8sError.IsNotFound(err) {
			log.WithError(err).Fatal("failed to find destination secret")
		}
	}

	if srcSecret, err = GetK8sSecret(context.TODO(), client, *srcSecretName); err != nil {
		if !k8sError.IsNotFound(err) {
			log.WithError(err).Fatal("failed to find source secret")
		}
	}

	if activeSecret, err = GetK8sSecret(context.TODO(), client, *activeSecretName); err != nil {
		if !k8sError.IsNotFound(err) {
			log.WithError(err).Info("failed to find active secret")
		}
	}

	if EqualInternalCerts(srcSecret, activeSecret) {
		// If srcSecret and dstSecret are the same, it doesn't mean it's already rolled out.
		// For example, activeSecret can be in a intermediate status.
		// So, only when srcSecret and activeSecret are the same, we exit.
		log.Info("Certificate is up-to-date.")
		return
	}

	// Fill srcSecret and dstSecret so they're not nil
	if srcSecret == nil {
		// TODO: We provide the secret all the time during testing, but we should generate one in the future.
		log.Fatal("Provide a internal cert named: ", *srcSecretName)
	}

	// When dst secret is absent, that means it's still using default certs.
	if dstSecret == nil {
		dstSecret = &corev1.Secret{
			Data: map[string][]byte{
				CACERT_FILENAME: []byte(LegacyCaCert),
				CERT_FILENAME:   []byte(LegacyCert),
				KEY_FILENAME:    []byte(LegacyKey),
			},
		}
	}

	if activeSecret == nil {
		secret = &corev1.Secret{
			TypeMeta: metav1.TypeMeta{
				Kind:       "Secret",
				APIVersion: "v1",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name: *activeSecretName,
				//Labels:      map[string]string{}, // TODO: fill these
				//Annotations: map[string]string{}, // TODO: fill these
			},
			Data: map[string][]byte{},
			Type: "Opaque",
		}
	} else {
		secret = activeSecret
	}

	for step := range []int{0, 1, 2} {
		// state: 0
		// merged cacert + old cert + old key
		// state: 1
		// merged cacert + new cert + new key
		// state: 2
		// new cacert + new cert + new key
		// TODO: CRD?
		// oldcert: {xxx, xxx, xxx}
		// newcert: {xxx, xxx, xxx}
		switch step {
		case (0):
			secret.Data[CACERT_FILENAME] = append(secret.Data[CACERT_FILENAME], dstSecret.Data[CACERT_FILENAME]...)
			secret.Data[CACERT_FILENAME] = append(secret.Data[CACERT_FILENAME], []byte("\n")...)
			secret.Data[CACERT_FILENAME] = append(secret.Data[CACERT_FILENAME], srcSecret.Data[CACERT_FILENAME]...)

			secret.Data[CERT_FILENAME] = dstSecret.Data[CERT_FILENAME]
			secret.Data[KEY_FILENAME] = dstSecret.Data[KEY_FILENAME]
		case (1):
			secret.Data[CACERT_FILENAME] = append(secret.Data[CACERT_FILENAME], dstSecret.Data[CACERT_FILENAME]...)
			secret.Data[CACERT_FILENAME] = append(secret.Data[CACERT_FILENAME], []byte("\n")...)
			secret.Data[CACERT_FILENAME] = append(secret.Data[CACERT_FILENAME], srcSecret.Data[CACERT_FILENAME]...)

			secret.Data[KEY_FILENAME] = srcSecret.Data[KEY_FILENAME]
			secret.Data[CERT_FILENAME] = srcSecret.Data[CERT_FILENAME]
		case (2):
			secret.Data[CACERT_FILENAME] = srcSecret.Data[CACERT_FILENAME]
			secret.Data[KEY_FILENAME] = srcSecret.Data[KEY_FILENAME]
			secret.Data[CERT_FILENAME] = srcSecret.Data[CERT_FILENAME]
		}

		// Replace secret with what we got from API server.
		secret, err = ApplyK8sSecret(context.TODO(), client, secret)

		if err != nil {
			//return nil, errors.Wrap(err, "failed to convert target secret")
			log.WithError(err).Fatal("failed to create/update dst secret")
		}

		// TODO: Find leader of controller.
		log.Info("Reloading controller's internal certificates")
		err = ReloadComponent(client, fields.OneTermEqualSelector("app", "neuvector-controller-pod").String())
		if err != nil {
			// TODO: rollback
			log.WithError(err).Fatal("failed to reload controller's internal cert. Rolling back.")
			return
		}

		log.Info("Reloading enforcer's internal certificates")
		err = ReloadComponent(client, fields.OneTermEqualSelector("app", "neuvector-enforcer-pod").String())
		if err != nil {
			// TODO: rollback
			log.WithError(err).Fatal("failed to reload enforcer's internal cert. Rolling back.")
			return
		}

		log.Info("Reloading scanner's internal certificates")
		err = ReloadComponent(client, fields.OneTermEqualSelector("app", "neuvector-scanner-pod").String())
		if err != nil {
			// TODO: rollback
			log.WithError(err).Fatal("failed to reload scanner's internal cert. Rolling back.")
			return
		}
	}

	// Write secret in a different name
	dstSecret.Data[CACERT_FILENAME] = secret.Data[CACERT_FILENAME]
	dstSecret.Data[KEY_FILENAME] = secret.Data[KEY_FILENAME]
	dstSecret.Data[CERT_FILENAME] = secret.Data[CERT_FILENAME]
	if _, err := ApplyK8sSecret(context.TODO(), client, secret); err != nil {
		log.WithError(err).Fatal("failed to write dest secret.")
	}

	log.Info("Internal certificates are migrated")
}

// Discover components based on label and call its reload API.
func ReloadComponent(client dynamic.Interface, selector string) error {
	item, err := client.Resource(
		schema.GroupVersionResource{
			Resource: "pods",
			Version:  "v1",
		},
	).Namespace(*namespace).List(context.TODO(), metav1.ListOptions{
		LabelSelector: selector,
	})

	if err != nil {
		return errors.Wrap(err, "failed to list pod")
	}

	var pods corev1.PodList
	err = runtime.DefaultUnstructuredConverter.
		FromUnstructured(item.UnstructuredContent(), &pods)
	if err != nil {
		return errors.Wrap(err, "failed to read pod list")
	}

	log.Infof("Reloading %d components", len(pods.Items))

	for _, pod := range pods.Items {
		// TODO: deal with terminating pods
		log.WithFields(log.Fields{
			"pod": pod.Status.PodIP,
		}).Info("triggering reloads")

		podAddress := net.JoinHostPort(pod.Status.PodIP, strconv.Itoa(*grpcPort))
		// TODO: better way to manage clients
		conn, err := NewGRPCClient(context.TODO(), podAddress, path.Join(*certPath, CACERT_FILENAME), path.Join(*certPath, CERT_FILENAME), path.Join(*certPath, KEY_FILENAME), *subjectCN)
		if err != nil {
			return errors.Wrap(err, "failed to create grpc client")
		}

		mgClient := share.NewMigrationServiceClient(conn)
		resp, err := mgClient.Reload(context.TODO(), &share.ReloadRequest{})
		if err != nil {
			return errors.Wrap(err, "failed to call reload API")
		}
		if !resp.Success {
			return fmt.Errorf("reload API returned error: %s", resp.Error)
		}
		log.WithFields(log.Fields{
			"resp": resp,
			"pod":  podAddress,
		}).Info("Certificate is reloaded")
	}
	return nil
}

func ApplyK8sSecret(ctx context.Context, client dynamic.Interface, secret *corev1.Secret) (*corev1.Secret, error) {
	var err error
	var item *unstructured.Unstructured
	var ret corev1.Secret
	unstructedSecret, err := runtime.DefaultUnstructuredConverter.ToUnstructured(secret)
	if err != nil {
		return nil, errors.Wrap(err, "failed to convert target secret")
	}

	if secret.ResourceVersion == "" {
		item, err = client.Resource(schema.GroupVersionResource{
			Resource: "secrets",
			Version:  "v1",
		}).Namespace(*namespace).Create(context.TODO(), &unstructured.Unstructured{Object: unstructedSecret}, metav1.CreateOptions{})
	} else {
		item, err = client.Resource(schema.GroupVersionResource{
			Resource: "secrets",
			Version:  "v1",
		}).Namespace(*namespace).Update(context.TODO(), &unstructured.Unstructured{Object: unstructedSecret}, metav1.UpdateOptions{})
	}
	if err != nil {
		return nil, errors.Wrap(err, "failed to update resource")
	}

	err = runtime.DefaultUnstructuredConverter.
		FromUnstructured(item.UnstructuredContent(), &ret)
	return &ret, err
}

func GetK8sSecret(ctx context.Context, client dynamic.Interface, name string) (*corev1.Secret, error) {
	item, err := client.Resource(
		schema.GroupVersionResource{
			Resource: "secrets",
			Version:  "v1",
		},
	).Namespace(*namespace).Get(ctx, name, metav1.GetOptions{})

	if err != nil {
		return nil, errors.Wrap(err, "failed to get secret")
	}

	var targetSecret corev1.Secret
	err = runtime.DefaultUnstructuredConverter.
		FromUnstructured(item.UnstructuredContent(), &targetSecret)
	if err != nil {
		return nil, errors.Wrap(err, "failed to parse target secret")
	}
	return &targetSecret, nil
}

func WaitUntilRolledOut(ctx context.Context, gr schema.GroupVersionResource, name string, client dynamic.Interface) error {
	// Implement kubectl rollout status
	// See https://github.com/kubernetes/kubectl/blob/master/pkg/cmd/rollout/rollout_status.go
	// TODO: kubectl plugin?

	// 1. Get controller deployment.
	item, err := client.Resource(gr).Namespace(*namespace).Get(context.TODO(), name, metav1.GetOptions{})
	if err != nil {
		// something wrong to get the deployment.  Give up.
		return errors.Wrap(err, "failed to get neuvector-controller-pod deployment")
	}
	var deployment appv1.Deployment
	err = runtime.DefaultUnstructuredConverter.
		FromUnstructured(item.UnstructuredContent(), &deployment)

	fieldSelector := fields.OneTermEqualSelector("metadata.name", deployment.Name).String()
	lw := &cache.ListWatch{
		ListFunc: func(options metav1.ListOptions) (runtime.Object, error) {
			options.FieldSelector = fieldSelector
			return client.Resource(gr).Namespace(deployment.Namespace).List(context.TODO(), options)
		},
		WatchFunc: func(options metav1.ListOptions) (watch.Interface, error) {
			options.FieldSelector = fieldSelector
			return client.Resource(gr).Namespace(deployment.Namespace).Watch(context.TODO(), options)
		},
	}

	statusViewer, err := polymorphichelpers.StatusViewerFor(deployment.GroupVersionKind().GroupKind())
	if err != nil {
		return errors.Wrap(err, "failed to find status viewer")
	}

	// Wait until deployment finishes.  Note: this could last forever if some of pods can't be deployed.
	_, err = watchtools.UntilWithSync(ctx, lw, &unstructured.Unstructured{}, nil, func(e watch.Event) (bool, error) {
		select {
		case <-ctx.Done():
			return false, ctx.Err()
		default:
		}
		switch t := e.Type; t {
		case watch.Added, watch.Modified:
			// TODO: examine if revision=0 is appropriate.
			status, done, err := statusViewer.Status(e.Object.(runtime.Unstructured), 0)
			if err != nil {
				return false, err
			}
			log.Println(status)

			// Quit waiting if the rollout is done
			if done {
				return true, nil
			}

			return false, nil

		case watch.Deleted:
			// We need to abort to avoid cases of recreation and not to silently watch the wrong (new) object
			return true, fmt.Errorf("object has been deleted")

		default:
			return true, fmt.Errorf("internal error: unexpected event %#v", e)
		}
	})
	return err
}

func Reload(conn *grpc.ClientConn) {
	// TODO: call reload
	// TODO: Should we depend on share?
	client := share.NewMigrationServiceClient(conn)
	client.Reload(context.TODO(), &share.ReloadRequest{})
}

func NewGRPCClient(ctx context.Context, endpoint string, cacertPath string, certPath string, keyPath string, subject string) (*grpc.ClientConn, error) {
	caCert, err := ioutil.ReadFile(cacertPath)
	if err != nil {
		return nil, err
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	// public/private keys
	cert, err := tls.LoadX509KeyPair(
		certPath,
		keyPath)
	if err != nil {
		return nil, err
	}

	config := &tls.Config{
		RootCAs:      caCertPool,
		Certificates: []tls.Certificate{cert},
		ServerName:   subject,
	}
	creds := credentials.NewTLS(config)

	return grpc.DialContext(ctx, endpoint,
		grpc.WithTransportCredentials(creds),
		grpc.WithDecompressor(grpc.NewGZIPDecompressor()),
		grpc.WithCompressor(grpc.NewGZIPCompressor()),
		grpc.WithDefaultCallOptions(grpc.FailFast(true)),
	)
}
