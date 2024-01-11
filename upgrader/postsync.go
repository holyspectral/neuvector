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
	"net/http"
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
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/tools/cache"
	watchtools "k8s.io/client-go/tools/watch"
	"k8s.io/client-go/util/retry"
	"k8s.io/kubectl/pkg/polymorphichelpers"
)

type ContainerStatus map[string]string

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
func containLegacyDefaultInternalCerts(ctx *cli.Context, client dynamic.Interface, namespace string) (bool, error) {
	item, err := client.Resource(
		schema.GroupVersionResource{
			Resource: "pods",
			Version:  "v1",
		},
	).Namespace(namespace).List(ctx.Context, metav1.ListOptions{
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

func DeleteK8sSecret(ctx context.Context, client dynamic.Interface, namespace string, secretName string) error {
	err := client.Resource(schema.GroupVersionResource{
		Resource: "secrets",
		Version:  "v1",
	}).Namespace(namespace).Delete(ctx, secretName, metav1.DeleteOptions{})
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
		}).Namespace(namespace).Create(ctx, &unstructured.Unstructured{Object: unstructedSecret}, metav1.CreateOptions{})
	} else {
		item, err = client.Resource(schema.GroupVersionResource{
			Resource: "secrets",
			Version:  "v1",
		}).Namespace(namespace).Update(ctx, &unstructured.Unstructured{Object: unstructedSecret}, metav1.UpdateOptions{})
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
	// kubectl rollout status
	// See https://github.com/kubernetes/kubectl/blob/master/pkg/cmd/rollout/rollout_status.go

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

func IsCertRevisionUpToDate(ctx *cli.Context, client dynamic.Interface, namespace string, rev string, selector string) (bool, error) {
	item, err := client.Resource(
		schema.GroupVersionResource{
			Resource: "pods",
			Version:  "v1",
		},
	).Namespace(namespace).List(ctx.Context, metav1.ListOptions{
		LabelSelector: selector,
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
		}).Info("Getting container status")

		var status ContainerStatus
		// TODO: timeout?
		res, err := http.Get(fmt.Sprintf("http://%s:%d/healthz", pod.Status.PodIP, 18500))
		if err != nil {
			return false, fmt.Errorf("failed to connect to healthz endpoint: %w", err)
		}
		err = json.NewDecoder(res.Body).Decode(&status)
		if err != nil {
			return false, fmt.Errorf("failed to unmarshal healthz response: %w", err)
		}

		if status["cert.revision"] != rev {
			log.WithFields(log.Fields{
				"rev":     rev,
				"pod":     pod.Status.PodIP,
				"podName": pod.Name,
			}).Info("container is not ready yet")
			return false, nil
		}
	}
	return true, nil
}

func IsAllCertRevisionUpToDate(ctx *cli.Context, client dynamic.Interface, namespace string, rev string) (bool, error) {
	if uptodate, err := IsCertRevisionUpToDate(ctx, client, rev, namespace, ControllerPodLabelSelector); err != nil {
		return false, fmt.Errorf("failed to check controller pods: %w", err)
	} else if !uptodate {
		return false, nil
	}

	if uptodate, err := IsCertRevisionUpToDate(ctx, client, rev, namespace, EnforcerPodLabelSelector); err != nil {
		return false, fmt.Errorf("failed to check enforcer pods: %w", err)
	} else if !uptodate {
		return false, nil
	}

	if uptodate, err := IsCertRevisionUpToDate(ctx, client, rev, namespace, ScannerPodLabelSelector); err != nil {
		return false, fmt.Errorf("failed to check scanner pods: %w", err)
	} else if !uptodate {
		return false, nil
	}
	return true, nil
}

func UpgradeInternalCerts(ctx *cli.Context, client dynamic.Interface, secret *corev1.Secret) error {
	if secret == nil {
		return errors.New("invalid secret")
	}

	namespace := ctx.String("namespace")
	var err error

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

	for step := range []int{0, 1, 2} {
		// state: 0
		// merged cacert + old cert + old key
		// state: 1
		// merged cacert + new cert + new key
		// state: 2
		// new cacert + new cert + new key
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
			return fmt.Errorf("failed to create/update dst secret: %w", err)
		}

		// Wait until all containers have the right revision.
		log.WithField("revision", secret.ResourceVersion).Info("secret is created/updated")

		uptodate := false
		err := wait.ExponentialBackoff(wait.Backoff{
			Steps:    10,
			Duration: 100 * time.Millisecond,
			Factor:   1.0,
			Jitter:   0.1,
		},
			func() (bool, error) {
				uptodate, err = IsAllCertRevisionUpToDate(ctx, client, namespace, secret.ResourceVersion)
				switch {
				case err == nil && uptodate:
					// complete
					return true, nil
				case !uptodate:
					// retry
					return false, nil
				default:
					// return error
					return false, err
				}
			})
		if err != nil {
			log.WithError(err).Error("failed to wait for secret adopted")
			return fmt.Errorf("failed to wait for secret adopted: %w", err)
		}

	}

	// Write dest secret and finish the rollout
	secret.Data[DEST_SECRET_PREFIX+CACERT_FILENAME] = secret.Data[NEW_SECRET_PREFIX+CACERT_FILENAME]
	secret.Data[DEST_SECRET_PREFIX+CERT_FILENAME] = secret.Data[NEW_SECRET_PREFIX+CERT_FILENAME]
	secret.Data[DEST_SECRET_PREFIX+KEY_FILENAME] = secret.Data[NEW_SECRET_PREFIX+KEY_FILENAME]

	if _, err := ApplyK8sSecret(ctx.Context, client, namespace, secret); err != nil {
		log.WithError(err).Fatal("failed to write dest secret.")
	}

	log.Info("Internal certificates are migrated")
	return nil
}

// Check if we should upgrade internal certs
func ShouldUpgradeInternalCert(ctx *cli.Context, secret *corev1.Secret) (bool, error) {
	if secret == nil {
		// No internal certificate.  We should upgrade it.
		return true, nil
	}
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
func InitializeInternalSecret(ctx *cli.Context, client dynamic.Interface, namespace string, freshInstall bool, secret *corev1.Secret) (*corev1.Secret, error) {
	var err error
	secretName := ctx.String("internal-secret-name")

	if secret != nil {
		log.Info("Updating internal secret.")
	} else {
		log.Info("Creating internal secret.")
		// Default secret is initialized using default certs. It will be updated later.
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
			Data: map[string][]byte{
				NEW_SECRET_PREFIX + CACERT_FILENAME: []byte(LegacyCaCert),
				NEW_SECRET_PREFIX + CERT_FILENAME:   []byte(LegacyCert),
				NEW_SECRET_PREFIX + KEY_FILENAME:    []byte(LegacyKey),

				DEST_SECRET_PREFIX + CACERT_FILENAME: []byte(LegacyCaCert),
				DEST_SECRET_PREFIX + CERT_FILENAME:   []byte(LegacyCert),
				DEST_SECRET_PREFIX + KEY_FILENAME:    []byte(LegacyKey),

				ACTIVE_SECRET_PREFIX + CACERT_FILENAME: []byte(LegacyCaCert),
				ACTIVE_SECRET_PREFIX + CERT_FILENAME:   []byte(LegacyCert),
				ACTIVE_SECRET_PREFIX + KEY_FILENAME:    []byte(LegacyKey),
			},
			Type: "Opaque",
		}
	}

	log.WithFields(log.Fields{
		"validity_days":  ctx.Int("ca-cert-validity-days"),
		"rsa-key-length": ctx.Int("rsa-key-length"),
	}).Info("creating/updating new certs...")

	caValidityDays := ctx.Int("ca-cert-validity-days")
	cacert, cakey, err := kv.GenerateCAWithRSAKey(GetInternalCACertTemplate(caValidityDays), ctx.Int("rsa-key-length"))
	if err != nil {
		return nil, fmt.Errorf("failed to generate ca cert: %w", err)
	}
	capair, err := tls.X509KeyPair(cacert, cakey)
	if err != nil {
		return nil, fmt.Errorf("failed to load ca key pair: %w", err)
	}

	log.WithFields(log.Fields{
		"cert":          string(cacert),
		"validity_days": caValidityDays,
	}).Debug("New cacert is created.")

	ca, err := x509.ParseCertificate(capair.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("failed to parse ca cert: %w", err)
	}

	certValidityDays := ctx.Int("cert-validity-days")
	cert, key, err := kv.GenerateTLSCertWithRSAKey(GetInternalCertTemplate(certValidityDays), ctx.Int("rsa-key-length"), ca, capair.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to generate TLS certificate: %w", err)
	}

	log.WithFields(log.Fields{
		"cert":          string(cert),
		"validity_days": certValidityDays,
	}).Debug("New cert is created.")

	// At this point, we have these keys/certs in PEM format:
	// 1. cacert in cacert, cakey
	// 2. internal certs in cert/key.
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
		// Upgrade case.  We should only provide NEW_SECRET and keep others intact
		secret.Data[NEW_SECRET_PREFIX+CACERT_FILENAME] = cacert
		secret.Data[NEW_SECRET_PREFIX+CERT_FILENAME] = cert
		secret.Data[NEW_SECRET_PREFIX+KEY_FILENAME] = key
	}

	// TODO: Make sure that every operation will update the secret's label, so it's well synchronized.
	// TODO: Use PATCH instead of CREATE/UPDATE.

	// If there is other instance running at the same time, this function is expected to cause conflict.
	var ret *corev1.Secret
	if ret, err = ApplyK8sSecret(ctx.Context, client, namespace, secret); err != nil {
		return nil, fmt.Errorf("failed to write dst secret: %w", err)
	}
	log.WithFields(log.Fields{
		"secret": secretName,
	}).Info("secret is created/updated")

	return ret, nil
}

// In post sync hook, we did a few things.
// 1. Check if the internal certs is already created.
// 2. Create it if it doesn't exist, trigger a rolling update on controller and exit. (fresh install case)
// 3. If it exists, examine the content.  If it's ok, just exit.  (upgrade from old, upgrade from new and reinstall)
// 4. If the cert is in the progress of upgrade, try to finish it. (Interrupted upgrade)
// 5. If the cert is not in progress, but its content is not ok, update it and trigger upgrade. (upgrade from old, upgrade from new and reinstall)
//
// Note: It's supposed to be only one upgrader job (post sync job) running at all time.
//
// empty => create secret => if secret is created and this is for fresh install, trigger rolling update and exit.
// not empty => do rolling update per its state.
func PostSyncHook(ctx *cli.Context) error {
	namespace := ctx.String("namespace")
	kubeconfig := ctx.String("kube-config")
	secretName := ctx.String("internal-secret-name")
	freshInstall := ctx.Bool("fresh-install")

	log.Info("Creating k8s client")

	client, err := NewK8sClient(kubeconfig)
	if err != nil {
		return fmt.Errorf("failed to create k8s client: %w", err)
	}

	// Initialization phase.

	// 1. Check if internal cert exists.  Create it if not exists.
	var secret *corev1.Secret
	var retSecret *corev1.Secret
	if secret, err = GetK8sSecret(ctx.Context, client, namespace, secretName); err != nil {
		if !k8sError.IsNotFound(err) {
			return fmt.Errorf("failed to find source secret: %w", err)
		}
	}

	// Check if we should update cert.  If not, exit

	// We create/update the secret in below scenario:
	// 1. Secret is not there.
	// 2. An option is given to force update the secret.
	// 3. Secret is not up-to-date, say it's expired, and no upgrade is in progress.
	if ctx.Bool("force-create-cert") {
		// If user doesn't specify cert and force-cert-cert is true, we create new cert regardless it's expired or legacy or not.
		log.Info("force-create-cert is true.  Will upgrade internal certs")
	} else {
		// Check if upgrader should still need to do its job.  If so, exit.
		if inprogress := IsUpgradeInProgress(ctx, secret); inprogress {
			log.Info("Cert rollout is still in progress.  Nothing to do here.")
			return nil
		}
		if shouldUpgrade, err := ShouldUpgradeInternalCert(ctx, secret); err != nil {
			return fmt.Errorf("failed to check if we should upgrade internal cert: %w", err)
		} else if !shouldUpgrade {
			log.Info("certificate is up-to-date")
			return nil
		} else {
			log.Info("we should update internal certificate")
		}
	}

	if retSecret, err = InitializeInternalSecret(ctx, client, namespace, freshInstall, secret); err != nil {
		return fmt.Errorf("failed to initialize internal secret: %w", err)
	}

	// Now we can create/update internal certs.
	log.Infof("Initializing internal secrets with retry: %+v", retry.DefaultRetry)
	err = retry.OnError(retry.DefaultRetry,
		func(error) bool {
			// Retry on all errors...k8s job will make it retry anyway.
			return true
		},
		func() error {
			// The main logic.

			// Fastpath. If it's a fresh install, no secret exists and the secret is created, it's a fresh install.
			// We just trigger controller's rolling update and exit.
			// Otherwise, go through the full rolling update.
			if secret == nil && retSecret != nil && freshInstall {
				// Everything is good now.  Exit.
				return nil
			}

			// Now we have certs ready. It's time to do rolling update.
			err = UpgradeInternalCerts(ctx, client, retSecret)
			if err != nil {
				return fmt.Errorf("failed to upgrade internal certs: %w", err)
			}

			return nil
		})
	if err != nil {
		if k8sError.IsAlreadyExists(err) {
			log.WithError(err).Debug("failed to create resource. Other init container created it. Can be safely ignored.")
		}
		return fmt.Errorf("failed to create internal certs: %w", err)
	}

	return nil
}
