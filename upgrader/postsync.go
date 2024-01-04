package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"net"
	"time"

	"errors"

	"github.com/neuvector/neuvector/controller/kv"
	log "github.com/sirupsen/logrus"
	"github.com/urfave/cli/v2"
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
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/tools/cache"
	watchtools "k8s.io/client-go/tools/watch"
	"k8s.io/client-go/util/retry"
	"k8s.io/kubectl/pkg/polymorphichelpers"
)

func GetRemoteCert(host string, port string, config *tls.Config) (*x509.Certificate, error) {
	// #nosec G402 InsecureSkipVerify is required to get remote cert anonymously.
	addr := net.JoinHostPort(host, port)

	conn, err := tls.Dial("tcp", addr, config)
	if err != nil {
		return nil, fmt.Errorf("failed to dial host %s: %w", host, err)
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
func containLegacyDefaultInternalCerts(client dynamic.Interface, namespace string) (bool, error) {
	item, err := client.Resource(
		schema.GroupVersionResource{
			Resource: "pods",
			Version:  "v1",
		},
	).Namespace(namespace).List(context.TODO(), metav1.ListOptions{
		LabelSelector: ControllerPodLabelSelector,
	})
	if err != nil {
		return false, fmt.Errorf("failed to find controller pods: %w", err)
	}

	var pods corev1.PodList
	err = runtime.DefaultUnstructuredConverter.
		FromUnstructured(item.UnstructuredContent(), &pods)
	if err != nil {
		return false, fmt.Errorf("failed to read pod list: %w", err)
	}

	for _, pod := range pods.Items {
		log.WithFields(log.Fields{
			"pod": pod.Status.PodIP,
		}).Info("Getting consul certs")

		// Check consul port to make sure consul is already up.
		cert, err := GetRemoteCert(pod.Status.PodIP, ControllerConsulPort, &tls.Config{InsecureSkipVerify: true})
		if err != nil {
			return false, fmt.Errorf("failed to get remote certs from %s: %w", pod.Status.PodIP, err)
		}

		// Convert cert back to pem for comparison
		var b bytes.Buffer
		err = pem.Encode(&b, &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		})
		if err != nil {
			return false, fmt.Errorf("failed to convert remote cert to PEM: %w", err)
		}

		log.Infof("Issuer Name: %s\n", cert.Issuer)
		log.Infof("Expiry: %s \n", cert.NotAfter.Format("2006-January-02"))
		log.Infof("Common Name: %s \n", cert.Issuer.CommonName)
		if b.String() == LegacyCert {
			log.Info("It's legacy cert.")
			return true, nil
		}
	}
	return false, nil
}

/*
// Discover components based on label and call its reload API.

	func ReloadComponent(ctx *cli.Context, client dynamic.Interface, namespace string, selector string) error {
		grpcPort := ctx.Int("migration-grpc-port")
		certPath := ctx.String("migration-cert-path")
		subjectCN := ctx.String("certificate-cn")

		item, err := client.Resource(
			schema.GroupVersionResource{
				Resource: "pods",
				Version:  "v1",
			},
		).Namespace(namespace).List(context.TODO(), metav1.ListOptions{
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

			podAddress := net.JoinHostPort(pod.Status.PodIP, strconv.Itoa(grpcPort))
			// TODO: better way to manage clients
			conn, err := NewGRPCClient(context.TODO(), podAddress, path.Join(certPath, CACERT_FILENAME), path.Join(certPath, CERT_FILENAME), path.Join(certPath, KEY_FILENAME), subjectCN)
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
*/
func DeleteK8sSecret(ctx context.Context, client dynamic.Interface, namespace string, secretName string) error {
	err := client.Resource(schema.GroupVersionResource{
		Resource: "secrets",
		Version:  "v1",
	}).Namespace(namespace).Delete(context.TODO(), secretName, metav1.DeleteOptions{})
	if err != nil {
		return fmt.Errorf("failed to delete secret %v: %w", secretName, err)
	}
	return nil
}

// Apply k8s secret.
// Make ResourceVersion empty if you don't want to overwrite existing data.
func ApplyK8sSecret(ctx context.Context, client dynamic.Interface, namespace string, secret *corev1.Secret) (*corev1.Secret, error) {
	var err error
	var item *unstructured.Unstructured
	var ret corev1.Secret
	unstructedSecret, err := runtime.DefaultUnstructuredConverter.ToUnstructured(secret)
	if err != nil {
		return nil, fmt.Errorf("failed to convert target secret: %w", err)
	}

	if secret.ResourceVersion == "" {
		item, err = client.Resource(schema.GroupVersionResource{
			Resource: "secrets",
			Version:  "v1",
		}).Namespace(namespace).Create(context.TODO(), &unstructured.Unstructured{Object: unstructedSecret}, metav1.CreateOptions{})
	} else {
		item, err = client.Resource(schema.GroupVersionResource{
			Resource: "secrets",
			Version:  "v1",
		}).Namespace(namespace).Update(context.TODO(), &unstructured.Unstructured{Object: unstructedSecret}, metav1.UpdateOptions{})
	}
	if err != nil {
		return nil, fmt.Errorf("failed to update resource: %w", err)
	}

	err = runtime.DefaultUnstructuredConverter.
		FromUnstructured(item.UnstructuredContent(), &ret)
	return &ret, err
}

func GetK8sSecret(ctx context.Context, client dynamic.Interface, namespace string, name string) (*corev1.Secret, error) {
	item, err := client.Resource(
		schema.GroupVersionResource{
			Resource: "secrets",
			Version:  "v1",
		},
	).Namespace(namespace).Get(ctx, name, metav1.GetOptions{})

	if err != nil {
		return nil, fmt.Errorf("failed to get secret: %w", err)
	}

	var targetSecret corev1.Secret
	err = runtime.DefaultUnstructuredConverter.
		FromUnstructured(item.UnstructuredContent(), &targetSecret)
	if err != nil {
		return nil, fmt.Errorf("failed to parse target secret: %w", err)
	}
	return &targetSecret, nil
}

func WaitUntilRolledOut(ctx context.Context, gr schema.GroupVersionResource, client dynamic.Interface, namespace string, name string) error {
	// Implemented kubectl rollout status
	// See https://github.com/kubernetes/kubectl/blob/master/pkg/cmd/rollout/rollout_status.go
	// TODO: kubectl plugin?

	// 1. Get controller deployment.
	item, err := client.Resource(gr).Namespace(namespace).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		// something wrong to get the deployment.  Give up.
		return fmt.Errorf("failed to get neuvector-controller-pod deployment: %w", err)
	}
	var deployment appv1.Deployment
	err = runtime.DefaultUnstructuredConverter.
		FromUnstructured(item.UnstructuredContent(), &deployment)
	if err != nil {
		return fmt.Errorf("failed to convert deployment: %w", err)
	}

	fieldSelector := fields.OneTermEqualSelector("metadata.name", deployment.Name).String()
	lw := &cache.ListWatch{
		ListFunc: func(options metav1.ListOptions) (runtime.Object, error) {
			options.FieldSelector = fieldSelector
			return client.Resource(gr).Namespace(deployment.Namespace).List(ctx, options)
		},
		WatchFunc: func(options metav1.ListOptions) (watch.Interface, error) {
			options.FieldSelector = fieldSelector
			return client.Resource(gr).Namespace(deployment.Namespace).Watch(ctx, options)
		},
	}

	statusViewer, err := polymorphichelpers.StatusViewerFor(deployment.GroupVersionKind().GroupKind())
	if err != nil {
		return fmt.Errorf("failed to find status viewer: %w", err)
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

func NewGRPCClient(ctx context.Context, endpoint string, cacertPath string, certPath string, keyPath string, subject string) (*grpc.ClientConn, error) {
	// #nosec G304 this is by design.
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
		MinVersion:   tls.VersionTLS12,
	}
	creds := credentials.NewTLS(config)

	return grpc.DialContext(ctx, endpoint,
		grpc.WithTransportCredentials(creds),
		grpc.WithDecompressor(grpc.NewGZIPDecompressor()), //lint:ignore SA1019 match with controller side code.
		grpc.WithCompressor(grpc.NewGZIPCompressor()),     //lint:ignore SA1019 match with controller side code.
		grpc.WithDefaultCallOptions(grpc.FailFast(true)),  //lint:ignore SA1019 match with controller side code.
	)
}

func WaitUntilDeployed(ctx context.Context,
	resource schema.GroupVersionResource,
	client dynamic.Interface,
	namespace string,
	resourceName string,
	timeout time.Duration) error {

	timeoutCtx, cancel := watchtools.ContextWithOptionalTimeout(ctx, timeout)
	defer cancel()
	err := WaitUntilRolledOut(timeoutCtx,
		resource,
		client,
		namespace,
		resourceName,
	)
	if err != nil {
		if k8sError.IsNotFound(err) {
			log.WithError(err).
				WithField("resource", resourceName).
				Info("The resource is not found.  This is normal when the components are not deployed.")
			return nil
		}
		return fmt.Errorf("failed to wait controller to rollout: %w", err)
	}
	return nil
}

func RestartResource(ctx *cli.Context, client dynamic.Interface, resourceGroup schema.GroupVersionResource, namespace string, resourceName string) error {
	log.WithFields(log.Fields{
		"resource":  resourceGroup,
		"namespace": namespace,
		"name":      resourceName,
	}).Info("restarting resource")

	switch resourceGroup.Resource {
	case "daemonsets":
	case "deployments":
	default:
		return fmt.Errorf("not supported resource type: %v", resourceGroup)
	}

	patch := map[string]interface{}{
		"spec": map[string]interface{}{
			"template": map[string]interface{}{
				"metadata": map[string]interface{}{
					"labels": map[string]interface{}{
						"restartedAt": time.Now().Format("2006-01-02-15-04-05"),
					},
				},
			},
		},
	}

	patchBytes, _ := json.Marshal(patch)

	_, err := client.Resource(resourceGroup).Namespace(namespace).Patch(ctx.Context, resourceName, types.MergePatchType, patchBytes, metav1.PatchOptions{})
	if err != nil {
		return fmt.Errorf("failed to update resource: %w", err)
	}

	return nil
}

func waitForContainersStart(ctx *cli.Context, client dynamic.Interface, namespace string) error {
	timeout := ctx.Duration("rollout-timeout")

	// Wait until the rollout of deployments/daemonsets completes.
	err := WaitUntilDeployed(ctx.Context,
		schema.GroupVersionResource{Group: "apps", Version: "v1", Resource: "deployments"},
		client,
		namespace,
		"neuvector-controller-pod",
		timeout)
	if err != nil {
		return fmt.Errorf("failed to wait controller to rollout: %w", err)
	}

	err = WaitUntilDeployed(ctx.Context,
		schema.GroupVersionResource{Group: "apps", Version: "v1", Resource: "daemonsets"},
		client,
		namespace,
		"neuvector-enforcer-pod",
		timeout)
	if err != nil {
		return fmt.Errorf("failed to wait enforcer to rollout: %w", err)
	}

	err = WaitUntilDeployed(ctx.Context,
		schema.GroupVersionResource{Group: "apps", Version: "v1", Resource: "deployments"},
		client,
		namespace,
		"neuvector-scanner-pod",
		timeout)
	if err != nil {
		return fmt.Errorf("failed to wait controller to rollout: %w", err)
	}

	err = WaitUntilDeployed(ctx.Context,
		schema.GroupVersionResource{Group: "apps", Version: "v1", Resource: "deployments"},
		client,
		namespace,
		"neuvector-registry-adapter-pod",
		timeout)
	if err != nil {
		return fmt.Errorf("failed to wait controller to rollout: %w", err)
	}

	// Check remote certificate and make sure that these servers are up.
	err = retry.OnError(retry.DefaultBackoff, func(err error) bool {
		log.WithError(err).Warn("failed to get remote internal cert.")
		return true
	}, func() error {
		containsLegacyCerts, err := containLegacyDefaultInternalCerts(client, namespace)
		if err != nil {
			return fmt.Errorf("failed to get remote internal certs: %w", err)
		}
		if containsLegacyCerts {
			log.Info("Legacy cert is detected")
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("failed to check existing certificate: %w", err)
	}
	return nil
}

func UpgradeInternalCerts(ctx *cli.Context, secretChanged bool) error {
	namespace := ctx.String("namespace")
	kubeconfig := ctx.String("kube-config")
	secretName := ctx.String("internal-secret-name")

	var secret *corev1.Secret

	client, err := NewK8sClient(kubeconfig)
	if err != nil {
		return fmt.Errorf("failed to create k8s client: %w", err)
	}

	// 2. NOTE: we don't wait for enforcer and scanner because their certs don't have to be changed at the same time.

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

	if secret, err = GetK8sSecret(ctx.Context, client, namespace, secretName); err != nil {
		if !k8sError.IsNotFound(err) {
			return fmt.Errorf("failed to find source secret: %w", err)
		}
		log.WithError(err).Info("no internal secret is created.  Nothing to do")
		return nil
	}

	if !IsCertPresent(secret, NEW_SECRET_PREFIX) {
		// It's decided previously that it doesn't need new internal cert.
		log.Info("No new certificate is specified")
		return nil
	}

	if !IsUpgradeInProgress(ctx, secret) {
		// When everything is in sync, no need to perform rollout.
		log.Info("Certificate is up-to-date.")

		// TODO: Only do this in fresh install.
		// Reload controller, so we know
		if secretChanged {
			log.Info("Reloading controller's internal certificates")
			err = RestartResource(ctx,
				client,
				schema.GroupVersionResource{Group: "apps", Version: "v1", Resource: "deployments"},
				namespace,
				"neuvector-controller-pod")
			if err != nil {
				log.WithError(err).Warn("failed to restart controller.  Skipping")
			}
		}

		return nil
	}

	if !IsCertPresent(secret, DEST_SECRET_PREFIX) {
		// No destination secret is specified.  Fill legacy cert in.
		secret.Data[DEST_SECRET_PREFIX+CACERT_FILENAME] = []byte(LegacyCaCert)
		secret.Data[DEST_SECRET_PREFIX+CERT_FILENAME] = []byte(LegacyCert)
		secret.Data[DEST_SECRET_PREFIX+KEY_FILENAME] = []byte(LegacyKey)
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
			// Combined CA
			secret.Data[ACTIVE_SECRET_PREFIX+CACERT_FILENAME] = nil
			secret.Data[ACTIVE_SECRET_PREFIX+CACERT_FILENAME] = append(secret.Data[ACTIVE_SECRET_PREFIX+CACERT_FILENAME], secret.Data[DEST_SECRET_PREFIX+CACERT_FILENAME]...)
			secret.Data[ACTIVE_SECRET_PREFIX+CACERT_FILENAME] = append(secret.Data[ACTIVE_SECRET_PREFIX+CACERT_FILENAME], []byte("\n")...)
			secret.Data[ACTIVE_SECRET_PREFIX+CACERT_FILENAME] = append(secret.Data[ACTIVE_SECRET_PREFIX+CACERT_FILENAME], secret.Data[NEW_SECRET_PREFIX+CACERT_FILENAME]...)

			// Old cert/key
			secret.Data[ACTIVE_SECRET_PREFIX+CERT_FILENAME] = secret.Data[DEST_SECRET_PREFIX+CERT_FILENAME]
			secret.Data[ACTIVE_SECRET_PREFIX+KEY_FILENAME] = secret.Data[DEST_SECRET_PREFIX+KEY_FILENAME]
		case (1):
			// Combined CA
			secret.Data[ACTIVE_SECRET_PREFIX+CACERT_FILENAME] = nil
			secret.Data[ACTIVE_SECRET_PREFIX+CACERT_FILENAME] = append(secret.Data[ACTIVE_SECRET_PREFIX+CACERT_FILENAME], secret.Data[DEST_SECRET_PREFIX+CACERT_FILENAME]...)
			secret.Data[ACTIVE_SECRET_PREFIX+CACERT_FILENAME] = append(secret.Data[ACTIVE_SECRET_PREFIX+CACERT_FILENAME], []byte("\n")...)
			secret.Data[ACTIVE_SECRET_PREFIX+CACERT_FILENAME] = append(secret.Data[ACTIVE_SECRET_PREFIX+CACERT_FILENAME], secret.Data[NEW_SECRET_PREFIX+CACERT_FILENAME]...)

			// New cert/key
			secret.Data[ACTIVE_SECRET_PREFIX+CERT_FILENAME] = secret.Data[NEW_SECRET_PREFIX+CERT_FILENAME]
			secret.Data[ACTIVE_SECRET_PREFIX+KEY_FILENAME] = secret.Data[NEW_SECRET_PREFIX+KEY_FILENAME]
		case (2):
			// New CA/cert/key
			secret.Data[ACTIVE_SECRET_PREFIX+CACERT_FILENAME] = secret.Data[NEW_SECRET_PREFIX+CACERT_FILENAME]
			secret.Data[ACTIVE_SECRET_PREFIX+CERT_FILENAME] = secret.Data[NEW_SECRET_PREFIX+CERT_FILENAME]
			secret.Data[ACTIVE_SECRET_PREFIX+KEY_FILENAME] = secret.Data[NEW_SECRET_PREFIX+KEY_FILENAME]
		}

		// Replace secret with what we got from API server.
		secret, err = ApplyK8sSecret(ctx.Context, client, namespace, secret)

		if err != nil {
			// TODO: retry
			//return nil, errors.Wrap(err, "failed to convert target secret")
			log.WithError(err).Fatal("failed to create/update dst secret")
		}

		// TODO: Find leader of controller.
		log.Info("Reloading controller's internal certificates")
		err = RestartResource(ctx,
			client,
			schema.GroupVersionResource{Group: "apps", Version: "v1", Resource: "deployments"},
			namespace,
			"neuvector-controller-pod")
		if err != nil {
			// TODO: rollback
			return fmt.Errorf("failed to reload controller's internal cert. Rolling back: %w", err)
		}

		log.Info("Reloading enforcer's internal certificates")
		err = RestartResource(ctx,
			client,
			schema.GroupVersionResource{Group: "apps", Version: "v1", Resource: "daemonsets"},
			namespace,
			"neuvector-enforcer-pod")
		if err != nil {
			// TODO: rollback
			return fmt.Errorf("failed to reload enforcer's internal cert. Rolling back: %w", err)
		}

		log.Info("Reloading scanner's internal certificates")
		err = RestartResource(ctx,
			client,
			schema.GroupVersionResource{Group: "apps", Version: "v1", Resource: "deployments"},
			namespace,
			"neuvector-scanner-pod")
		if err != nil {
			// TODO: rollback
			return fmt.Errorf("failed to reload scanner's internal cert. Rolling back: %w", err)
		}

		log.Info("Reloading registry's internal certificates")
		err = RestartResource(ctx,
			client,
			schema.GroupVersionResource{Group: "apps", Version: "v1", Resource: "deployments"},
			namespace,
			"neuvector-registry-adapter-pod")
		if err != nil {
			// TODO: rollback
			return fmt.Errorf("failed to reload scanner's internal cert. Rolling back: %w", err)
		}

		err = waitForContainersStart(ctx, client, namespace)
		if err != nil {
			return fmt.Errorf("failed to wait for other containers start: %w", err)
		}
	}

	// Write dest secret and finish the rollout
	secret.Data[DEST_SECRET_PREFIX+CACERT_FILENAME] = secret.Data[NEW_SECRET_PREFIX+CACERT_FILENAME]
	secret.Data[DEST_SECRET_PREFIX+CERT_FILENAME] = secret.Data[NEW_SECRET_PREFIX+CERT_FILENAME]
	secret.Data[DEST_SECRET_PREFIX+KEY_FILENAME] = secret.Data[NEW_SECRET_PREFIX+KEY_FILENAME]

	if _, err := ApplyK8sSecret(context.TODO(), client, namespace, secret); err != nil {
		log.WithError(err).Fatal("failed to write dest secret.")
	}

	log.Info("Internal certificates are migrated")
	return nil
}

// Check controller's deployment to see if it's still not rolled out.
// If yes, it's a fresh install.  If no, it's during a rolling update.
func IsFreshInstall(ctx *cli.Context, client dynamic.Interface, namespace string, ownerUID string) (bool, error) {

	item, err := client.Resource(
		schema.GroupVersionResource{
			Resource: "pods",
			Version:  "v1",
		},
	).Namespace(namespace).List(context.TODO(), metav1.ListOptions{
		LabelSelector: ControllerPodLabelSelector,
		FieldSelector: RunningPodFieldSelector,
	})
	if err != nil {
		return false, fmt.Errorf("failed to find controller pods: %w", err)
	}

	var pods corev1.PodList
	err = runtime.DefaultUnstructuredConverter.
		FromUnstructured(item.UnstructuredContent(), &pods)
	if err != nil {
		return false, fmt.Errorf("failed to read pod list: %w", err)
	}

	// Examine all controller pods to see if their certificate expires or they're still using legacy certs.
	for _, pod := range pods.Items {
		log.WithFields(log.Fields{
			"pod": pod.Status.PodIP,
		}).Debug("Getting gRPC and consul certs")

		if len(pod.OwnerReferences) != 1 {
			return false, errors.New("more than one owner reference are detected")
		}
		if ownerUID != string(pod.OwnerReferences[0].UID) {
			log.Info("controller pods belonging to other replicaset is detected.  We're during a rolling update.")
			return false, nil
		}
	}

	log.Info("All controllers coming from the same deployment. It's a fresh install.")
	return true, nil
}

// Check if we should upgrade internal certs
func ShouldUpgradeInternalCert(ctx *cli.Context, secret *corev1.Secret) (bool, error) {
	renewThreshold := ctx.Duration("expiry-cert-threshold")

	block, _ := pem.Decode(secret.Data[DEST_SECRET_PREFIX+CERT_FILENAME])
	if block == nil || block.Type != "CERTIFICATE" {
		return false, errors.New("failed to decode certificate")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return false, fmt.Errorf("failed to parse x509 certificate: %w", err)
	}
	if time.Now().After(cert.NotAfter.Add(-renewThreshold)) {
		log.WithFields(log.Fields{
			"expiry":    cert.NotAfter,
			"threshold": renewThreshold,
		}).Info("Nearly expired certificate is detected")
		return true, nil
	}
	return false, nil
}

// This function is meant to be called during pre-install/pre-upgrade/pre-sync hook.
// If it's a fresh-install, create an internal certificate that we can use directly.
// If it's a upgrade, leave it as it is.
// Post-upgrade/post-sync hook should deal with it.
func InitializeInternalSecret(ctx *cli.Context, client dynamic.Interface, namespace string, ownerUID string) (bool, error) {
	if ctx.Bool("user-managed-cert") {
		// We should never update user-specified cert, so nothing to do here.
		log.Info("User has specified internal certs")
		return false, nil
	}

	var secret *corev1.Secret
	var err error
	secretName := ctx.String("internal-secret-name")

	if secret, err = GetK8sSecret(ctx.Context, client, namespace, secretName); err != nil {
		if !k8sError.IsNotFound(err) {
			return false, fmt.Errorf("failed to read internal secret: %w", err)
		}
	}

	// TODO: fix this
	freshInstall, err := IsFreshInstall(ctx, client, namespace, ownerUID)
	if err != nil {
		return false, fmt.Errorf("failed to check if this is fresh install or rolling update: %w", err)
	}

	if secret != nil {
		log.Info("Internal secret is found.")

		// Check if upgrader should still need to do its job.  If so, exit.
		beingUpgraded := IsUpgradeInProgress(ctx, secret)
		if beingUpgraded {
			log.Info("Cert rollout is still in progress.  We shouldn't change internal cert.")
			return false, nil
		}

		// Check if we should update cert.  If not, exit
		shouldUpgradeCert := false
		if ctx.Bool("force-create-cert") {
			// If user doesn't specify cert and force-cert-cert is true, we create new cert regardless it's expired or legacy or not.
			log.Info("force-create-cert is true.  Will upgrade internal certs")
			shouldUpgradeCert = true
		} else {
			shouldUpgradeCert, err = ShouldUpgradeInternalCert(ctx, secret)
			if err != nil {
				return false, fmt.Errorf("failed to check if we should upgrade internal cert: %w", err)
			}
		}

		if !shouldUpgradeCert {
			// Nothing to do
			log.Info("No need to upgrade internal cert.")
			return false, nil
		}
	} else {
		log.Info("Internal secret is not found.")
		secret = &corev1.Secret{

			TypeMeta: metav1.TypeMeta{
				Kind:       "Secret",
				APIVersion: "v1",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name: secretName,
				//Labels:      map[string]string{}, // TODO: fill these
				//Annotations: map[string]string{}, // TODO: fill these
			},
			Data: map[string][]byte{},
			Type: "Opaque",
		}
	}

	log.WithFields(log.Fields{
		"validity_days":  ctx.Int("ca-cert-validity-days"),
		"rsa-key-length": ctx.Int("rsa-key-length"),
	}).Info("creating new certs...")

	// Note: We have a few factors here.
	// 1. Fresh intall or upgrade.
	// 2. Whether internal cert is already supplied. (helm should know this. TODO: helm to pass user-managed-cert.)
	// 3. Whether internal cert is legacy or expiring.  (Checked in ShouldUpgradeInternalCert)
	// TODO: Move kv code to share.

	caValidityDays := ctx.Int("ca-cert-validity-days")
	cacert, cakey, err := kv.GenerateCAWithRSAKey(GetInternalCACertTemplate(caValidityDays), ctx.Int("rsa-key-length"))
	if err != nil {
		return false, fmt.Errorf("failed to generate ca cert: %w", err)
	}
	capair, err := tls.X509KeyPair(cacert, cakey)
	if err != nil {
		return false, fmt.Errorf("failed to load ca key pair: %w", err)
	}

	log.WithFields(log.Fields{
		"cert":          string(cacert),
		"validity_days": caValidityDays,
	}).Debug("New cacert is created.")

	ca, err := x509.ParseCertificate(capair.Certificate[0])
	if err != nil {
		return false, fmt.Errorf("failed to parse ca cert: %w", err)
	}

	certValidityDays := ctx.Int("cert-validity-days")
	cert, key, err := kv.GenerateTLSCertWithRSAKey(GetInternalCertTemplate(certValidityDays), ctx.Int("rsa-key-length"), ca, capair.PrivateKey)
	if err != nil {
		return false, fmt.Errorf("failed to generate TLS certificate: %w", err)
	}

	log.WithFields(log.Fields{
		"cert":          string(cert),
		"validity_days": certValidityDays,
	}).Debug("New cert is created.")

	// At this point, we have these keys/certs in PEM format:
	// 1. cacert in cacert, cakey
	// 2. internal certs in cert/key.

	// TODO: Look into optional secret mount

	if freshInstall {
		// Fresh install case.  We should apply to NEW_SECRET_NAME, DEST_SECRET_NAME and ACTIVE_SECRET_NAME

		secret.Data[NEW_SECRET_PREFIX+CACERT_FILENAME] = cacert
		secret.Data[NEW_SECRET_PREFIX+CERT_FILENAME] = cert
		secret.Data[NEW_SECRET_PREFIX+KEY_FILENAME] = key

		secret.Data[DEST_SECRET_PREFIX+CACERT_FILENAME] = cacert
		secret.Data[DEST_SECRET_PREFIX+CERT_FILENAME] = cert
		secret.Data[DEST_SECRET_PREFIX+KEY_FILENAME] = key

		secret.Data[ACTIVE_SECRET_PREFIX+CACERT_FILENAME] = cacert
		secret.Data[ACTIVE_SECRET_PREFIX+CERT_FILENAME] = cert
		secret.Data[ACTIVE_SECRET_PREFIX+KEY_FILENAME] = key
	} else {
		// Upgrade case.  We should only provide NEW_SECRET_NAME.
		secret.Data[NEW_SECRET_PREFIX+CACERT_FILENAME] = cacert
		secret.Data[NEW_SECRET_PREFIX+CERT_FILENAME] = cert
		secret.Data[NEW_SECRET_PREFIX+KEY_FILENAME] = key

		secret.Data[DEST_SECRET_PREFIX+CACERT_FILENAME] = nil
		secret.Data[DEST_SECRET_PREFIX+CERT_FILENAME] = nil
		secret.Data[DEST_SECRET_PREFIX+KEY_FILENAME] = nil

		secret.Data[ACTIVE_SECRET_PREFIX+CACERT_FILENAME] = nil
		secret.Data[ACTIVE_SECRET_PREFIX+CERT_FILENAME] = nil
		secret.Data[ACTIVE_SECRET_PREFIX+KEY_FILENAME] = nil
	}

	// TODO: Make sure that every operation will update the secret's label, so it's well synchronized.
	// TODO: Use PATCH instead of CREATE/UPDATE to reduce attack surface.

	// If there is other instance running at the same time, this function is expected to cause conflict.
	if _, err := ApplyK8sSecret(ctx.Context, client, namespace, secret); err != nil {
		return false, fmt.Errorf("failed to write dst secret: %w", err)
	}
	log.WithFields(log.Fields{
		"secret": secretName,
	}).Info("secret is created/updated")

	return true, nil
}

func PostSyncHook(ctx *cli.Context) error {
	namespace := ctx.String("namespace")
	kubeconfig := ctx.String("kube-config")

	log.Info("Creating k8s client")

	client, err := NewK8sClient(kubeconfig)
	if err != nil {
		return fmt.Errorf("failed to create k8s client: %w", err)
	}

	// Getting pod's owner UID.
	// TODO: This can be retrived via deployment spec.
	log.Info("Getting this pod's owner UID")

	helmDeploymentUID, err := GetHelmDeploymentUID(ctx, client, namespace)
	if err != nil {
		return fmt.Errorf("failed to get this pod's deployment UID: %w", err)
	}

	log.WithField("uid", helmDeploymentUID).Info("retrieved deployment UID successfully")

	// Initialize internal secrets.

	secretUpdated := false
	log.Info("Initializing internal secrets")
	err = retry.RetryOnConflict(retry.DefaultRetry, func() error {
		if secretUpdated, err = InitializeInternalSecret(ctx, client, namespace, helmDeploymentUID); err != nil {
			return fmt.Errorf("failed to initialize internal secret: %w", err)
		}
		return nil
	})
	if err != nil {
		if k8sError.IsAlreadyExists(err) {
			log.WithError(err).Debug("failed to create resource. Other init container created it. Can be safely ignored.")
		}
		return err
	}

	err = UpgradeInternalCerts(ctx, secretUpdated)
	if err != nil {
		return fmt.Errorf("failed to upgrade internal certs: %w", err)
	}
	return nil
}
