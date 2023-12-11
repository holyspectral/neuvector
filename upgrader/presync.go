package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"time"

	"github.com/neuvector/neuvector/controller/kv"
	"github.com/neuvector/neuvector/share/cluster"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/urfave/cli/v2"
	corev1 "k8s.io/api/core/v1"
	k8sError "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
)

func GetInternalCACertTemplate(validDays int) *x509.Certificate {
	return &x509.Certificate{
		SerialNumber: big.NewInt(5029),
		Subject: pkix.Name{
			Country:      []string{"US"},
			Province:     []string{"California"},
			Organization: []string{"NeuVector Inc."},
			CommonName:   "NeuVector",
		},
		NotBefore:             time.Now().Add(time.Hour * -1), // Give it some room for timing skew.
		NotAfter:              time.Now().AddDate(0, 0, validDays),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageKeyEncipherment,
		BasicConstraintsValid: true,
	}
}

func GetInternalCertTemplate(validDays int) *x509.Certificate {
	return &x509.Certificate{
		SerialNumber: big.NewInt(5030),
		Subject: pkix.Name{
			Country:      []string{"US"},
			Province:     []string{"California"},
			Organization: []string{"NeuVector Inc."},
			CommonName:   "NeuVector",
		},
		NotBefore:    time.Now().Add(time.Hour * -1), // Give it some room for timing skew.
		NotAfter:     time.Now().AddDate(0, 0, validDays),
		SubjectKeyId: []byte{1, 2, 3, 4, 6},
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
	}
}

func ResourceExists(ctx *cli.Context, client dynamic.Interface, resource schema.GroupVersionResource, namespace string, name string) (bool, error) {
	_, err := client.Resource(resource).Namespace(namespace).Get(ctx.Context, name, metav1.GetOptions{})
	if err == nil {
		return true, nil
	}
	if k8sError.IsNotFound(err) {
		return false, nil
	} else {
		return false, err
	}
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

func IsSignedByLegacyCacert(cacert []byte, cert *x509.Certificate) (bool, error) {

	roots := x509.NewCertPool()
	ok := roots.AppendCertsFromPEM([]byte(LegacyCaCert))
	if !ok {
		return false, errors.New("failed to append legacy cacert")
	}

	opts := x509.VerifyOptions{
		Roots:         roots,
		DNSName:       cluster.InternalCertCN,
		Intermediates: x509.NewCertPool(),
	}

	if _, err := cert.Verify(opts); err != nil {
		if errors.As(err, x509.UnknownAuthorityError{}) {
			return false, nil
		} else {
			return false, errors.Wrap(err, "failed to verify certificate")
		}
	}

	return true, nil
}

// Check if a legacy internal cert is still being used.
// TODO: Only call this during pre-install hook.
// TODO: Consider argocd and operator-sdk
func ShouldUpgradeInternalCert(ctx *cli.Context, client dynamic.Interface, namespace string) (bool, error) {
	if ctx.Bool("user-managed-cert") {
		// We should never update user-specified cert.
		log.Info("User has specified internal certs")
		return false, nil
	}
	if ctx.Bool("force-create-cert") {
		// If user doesn't specify cert and force-cert-cert is true, we create new cert regardless it's expired or legacy or not.
		log.Info("force-create-cert is true.  Will upgrade internal certs")
		return true, nil
	}

	renewThreshold := ctx.Duration("expiry-cert-threshold")

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
		}).Debug("Getting gRPC and consul certs")

		cert, err := GetRemoteCert(pod.Status.PodIP, ControllerConsulPort)
		if err != nil {
			return false, errors.Wrapf(err, "failed to get remote certs from: %s", pod.Status.PodIP)
		}

		if time.Now().After(cert.NotAfter.Add(-renewThreshold)) {
			log.WithFields(log.Fields{
				"expiry":    cert.NotAfter,
				"namespace": namespace,
				"pod":       pod.Name,
				"host":      pod.Status.PodIP,
				"threshold": renewThreshold,
			}).Info("Nearly expired certificate is detected")
			return true, nil
		}
		// Check if it's signed by known cert LegacyCaCert
		isSignedByLegacy, err := IsSignedByLegacyCacert([]byte(LegacyCaCert), cert)
		if err != nil {
			return false, errors.Wrapf(err, "failed to check if it's signed by legacy cacert")
		}
		if isSignedByLegacy {
			return true, nil
		}
	}
	return false, nil
}

// This function checks if any resource listed exists or not.
func FindAnyRequiredResource(ctx *cli.Context, client dynamic.Interface, namespace string) (bool, error) {
	// We have to evaluate controller, enforcer, scanner to make sure since they're all optional.
	// If these components are not availabe, which means we don't have to upgrade internal certs.
	// In this case we can assume it's a fresh instalCheckl safely.

	// Note: we should check its upstream resource, i.e., deployment and/or daemonset.
	// Otherwise, it would be prone to race condition.
	resources := []struct {
		resource schema.GroupVersionResource
		name     string
	}{
		{
			schema.GroupVersionResource{
				Group:    "apps",
				Version:  "v1",
				Resource: "deployments",
			},
			"neuvector-controller-pod",
		},
		{
			schema.GroupVersionResource{
				Group:    "apps",
				Version:  "v1",
				Resource: "deployments",
			},
			"neuvector-scanner-pod",
		},
		{
			schema.GroupVersionResource{
				Group:    "apps",
				Version:  "v1",
				Resource: "daemonsets",
			},
			"neuvector-enforcer-pod",
		},
	}

	for _, v := range resources {
		exists, err := ResourceExists(ctx, client, v.resource, namespace, v.name)
		if err != nil {
			return false, errors.Wrap(err, "failed to retrieve resources")
		}
		if exists {
			return true, nil
		}
	}
	return false, nil
}

// This function is meant to be called during pre-install/pre-upgrade/pre-sync hook.
// If it's a fresh-install, create an internal certificate that we can use directly.
// If it's a upgrade, leave it as it is.
// Post-upgrade/post-sync hook should deal with it.
func InitializeInternalSecret(ctx *cli.Context, client dynamic.Interface, namespace string) error {

	shouldUpgradeCert, err := ShouldUpgradeInternalCert(ctx, client, namespace)
	if err != nil {
		return errors.Wrap(err, "failed to check if we should upgrade internal cert")
	}
	if !shouldUpgradeCert {
		// Nothing to do
		log.Info("No need to upgrade internal cert.  Finishing.")
		return nil
	}

	isUpgrade, err := FindAnyRequiredResource(ctx, client, namespace)
	if err != nil {
		return errors.Wrap(err, "failed to find existing resources")
	}

	if isUpgrade {
		log.Info("Detect existing resources.  We're doing upgrade.")
	} else {
		log.Info("Couldn't detect existing resources.  We're doing installation.")
	}

	// Note: We have a few factors here.
	// 1. Fresh intall or upgrade.
	// 2. Whether internal cert is already supplied. (helm should know this)
	// 3. Whether internal cert is legacy or expiring.  (Checked in ShouldUpgradeInternalCert)
	// TODO: If there is a failing pod, should we abort?
	// TODO: Move kv code to share.

	caValidityDays := ctx.Int("ca-cert-validity-days")
	cacert, cakey, err := kv.GenerateCAWithRSAKey(GetInternalCACertTemplate(caValidityDays), ctx.Int("rsa-key-length"))
	if err != nil {
		return errors.Wrap(err, "failed to generate ca cert")
	}
	capair, err := tls.X509KeyPair(cacert, cakey)
	if err != nil {
		return errors.Wrap(err, "failed to load ca key pair")
	}

	log.WithFields(log.Fields{
		"cert":          string(cacert),
		"validity_days": caValidityDays,
	}).Info("New cacert is created.")

	ca, err := x509.ParseCertificate(capair.Certificate[0])
	if err != nil {
		return errors.Wrap(err, "failed to parse ca cert")
	}

	certValidityDays := ctx.Int("cert-validity-days")
	cert, key, err := kv.GenerateTLSCertWithRSAKey(GetInternalCertTemplate(certValidityDays), ctx.Int("rsa-key-length"), ca, capair.PrivateKey)
	if err != nil {
		return errors.Wrap(err, "failed to generate TLS certificate")
	}

	log.WithFields(log.Fields{
		"cert":          string(cert),
		"validity_days": certValidityDays,
	}).Info("New cert is created.")

	// At this point, we have these keys/certs in PEM format:
	// 1. cacert in cacert, cakey
	// 2. internal certs in cert/key.

	secret := &corev1.Secret{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Secret",
			APIVersion: "v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			//Labels:      map[string]string{}, // TODO: fill these
			//Annotations: map[string]string{}, // TODO: fill these
		},
		Data: map[string][]byte{
			CACERT_FILENAME: cacert,
			CERT_FILENAME:   cert,
			KEY_FILENAME:    key,
		},
		Type: "Opaque",
	}

	// TODO: If hook runs the second time?
	// TODO: Need to figure out a cluster-wise lock.
	// TODO: Support upgrade cert.

	if !isUpgrade {
		// Fresh install case
		secret.Name = ctx.String("dest-secret-name")
		if _, err := ApplyK8sSecret(ctx.Context, client, namespace, secret); err != nil {
			return errors.Wrap(err, "failed to write dst secret")
		}
		log.WithFields(log.Fields{
			"secret": secret.Name,
		}).Info("secret is created")
		secret.Name = ctx.String("active-secret-name")
		if _, err := ApplyK8sSecret(ctx.Context, client, namespace, secret); err != nil {
			return errors.Wrap(err, "failed to write active secret")
		}
		log.WithFields(log.Fields{
			"secret": secret.Name,
		}).Info("secret is created")
		secret.Name = ctx.String("new-secret-name")
		if _, err := ApplyK8sSecret(ctx.Context, client, namespace, secret); err != nil {
			return errors.Wrap(err, "failed to write active secret")
		}
		log.WithFields(log.Fields{
			"secret": secret.Name,
		}).Info("secret is created")

		return nil
	}

	// Upgrade case
	secret.Name = ctx.String("new-secret-name")
	if _, err := ApplyK8sSecret(ctx.Context, client, namespace, secret); err != nil {
		return errors.Wrap(err, "failed to write src secret")
	}
	log.Info("pre-sync hook completes")
	return nil

}

func PreSyncHook(ctx *cli.Context) error {
	namespace := ctx.String("namespace")
	kubeconfig := ctx.String("kube-config")

	locker, err := CreateLocker(namespace)

	locker.Lock()
	log.Info("lock is acquired.")

	defer locker.Unlock()

	client, err := NewK8sClient(kubeconfig)
	if err != nil {
		return errors.Wrap(err, "failed to create k8s client")
	}
	if err := InitializeInternalSecret(ctx, client, namespace); err != nil {
		return errors.Wrap(err, "failed to initialize internal secret")
	}
	return nil
}
