package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"reflect"
	"time"

	"github.com/neuvector/neuvector/controller/kv"
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

const (
	UPGRADER_JOB_NAME = "neuvector-upgrader-job"
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

func IsCertPresent(secret *corev1.Secret, prefix string) bool {
	if _, ok := secret.Data[prefix+CACERT_FILENAME]; !ok {
		return false
	}
	if _, ok := secret.Data[prefix+CERT_FILENAME]; !ok {
		return false
	}
	if _, ok := secret.Data[prefix+KEY_FILENAME]; !ok {
		return false
	}
	return true
}

func IsSameCert(secret *corev1.Secret, prefix1 string, prefix2 string) bool {
	return reflect.DeepEqual(secret.Data[prefix1+CACERT_FILENAME], secret.Data[prefix2+CACERT_FILENAME]) &&
		reflect.DeepEqual(secret.Data[prefix1+CERT_FILENAME], secret.Data[prefix2+CERT_FILENAME]) &&
		reflect.DeepEqual(secret.Data[prefix1+KEY_FILENAME], secret.Data[prefix2+KEY_FILENAME])
}

// The upgrader will be working on moving newSecret to activeSecret and finally destSecret.
// That means, after upgrade, these three secrets should be the same.
// If they're the same, return false, otherwise, return true.
func IsUpgradeInProgress(ctx *cli.Context, secret *corev1.Secret) bool {
	return !IsSameCert(secret, NEW_SECRET_PREFIX, DEST_SECRET_PREFIX) || !IsSameCert(secret, NEW_SECRET_PREFIX, ACTIVE_SECRET_PREFIX)
}

func GetPodOwnerUID(ctx *cli.Context, client dynamic.Interface, namespace string) (string, error) {
	item, err := client.Resource(
		schema.GroupVersionResource{
			Resource: "pods",
			Version:  "v1",
		},
	).Namespace(namespace).Get(context.TODO(), os.Getenv("PODNAME"), metav1.GetOptions{})

	if err != nil {
		return "", errors.Wrap(err, "failed to get this container's pod information")
	}

	var pod corev1.Pod
	err = runtime.DefaultUnstructuredConverter.
		FromUnstructured(item.UnstructuredContent(), &pod)
	if err != nil {
		return "", errors.Wrap(err, "failed to convert to pod")
	}

	if len(pod.OwnerReferences) != 1 {
		return "", errors.New("more than one owner reference are detected")
	}
	return string(pod.OwnerReferences[0].UID), nil
}

// Check if all controller pods belonging to the same replica set.
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
		return false, errors.Wrap(err, "failed to find controller pods")
	}

	var pods corev1.PodList
	err = runtime.DefaultUnstructuredConverter.
		FromUnstructured(item.UnstructuredContent(), &pods)
	if err != nil {
		return false, errors.Wrap(err, "failed to read pod list")
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
	if ctx.Bool("force-create-cert") {
		// If user doesn't specify cert and force-cert-cert is true, we create new cert regardless it's expired or legacy or not.
		log.Info("force-create-cert is true.  Will upgrade internal certs")
		return true, nil
	}

	renewThreshold := ctx.Duration("expiry-cert-threshold")

	block, _ := pem.Decode(secret.Data[DEST_SECRET_PREFIX+CERT_FILENAME])
	if block == nil || block.Type != "CERTIFICATE" {
		return false, errors.New("failed to decode certificate")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return false, errors.Wrap(err, "failed to parse x509 certificate")
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
func InitializeInternalSecret(ctx *cli.Context, client dynamic.Interface, namespace string, ownerUID string) error {
	if ctx.Bool("user-managed-cert") {
		// We should never update user-specified cert, so nothing to do here.
		log.Info("User has specified internal certs")
		return nil
	}

	var secret *corev1.Secret
	var err error
	secretName := ctx.String("internal-secret-name")

	if secret, err = GetK8sSecret(ctx.Context, client, namespace, secretName); err != nil {
		if !k8sError.IsNotFound(err) {
			return errors.Wrap(err, "failed to read internal secret")
		}
	}

	freshInstall, err := IsFreshInstall(ctx, client, namespace, ownerUID)
	if err != nil {
		return errors.Wrap(err, "failed to check if this is fresh install or rolling update")
	}

	if secret != nil {
		log.Info("Internal secret is found.")

		// Check if upgrader should still need to do its job.  If so, exit.
		beingUpgraded := IsUpgradeInProgress(ctx, secret)
		if beingUpgraded {
			log.Info("Cert rollout is still in progress.  We shouldn't change internal cert.")
			return nil
		}

		// Check if we should update cert.  If not, exit
		shouldUpgradeCert, err := ShouldUpgradeInternalCert(ctx, secret)
		if err != nil {
			return errors.Wrap(err, "failed to check if we should upgrade internal cert")
		}
		if !shouldUpgradeCert {
			// Nothing to do
			log.Info("No need to upgrade internal cert.")
			return nil
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
		return errors.Wrap(err, "failed to generate ca cert")
	}
	capair, err := tls.X509KeyPair(cacert, cakey)
	if err != nil {
		return errors.Wrap(err, "failed to load ca key pair")
	}

	log.WithFields(log.Fields{
		"cert":          string(cacert),
		"validity_days": caValidityDays,
	}).Debug("New cacert is created.")

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
		return errors.Wrap(err, "failed to write dst secret")
	}
	log.WithFields(log.Fields{
		"secret": secretName,
	}).Info("secret is created/updated")

	return nil
}

func PreSyncHook(ctx *cli.Context) error {
	skip := ctx.Bool("skip-cert-creation")

	if skip {
		log.Info("skipping certificate creation")
		return nil
	}

	namespace := ctx.String("namespace")
	kubeconfig := ctx.String("kube-config")

	log.Info("Creating k8s client")

	client, err := NewK8sClient(kubeconfig)
	if err != nil {
		return errors.Wrap(err, "failed to create k8s client")
	}

	log.Info("Getting this pod's owner UID")

	ownerUID, err := GetPodOwnerUID(ctx, client, namespace)
	if err != nil {
		return errors.Wrap(err, "failed to get this pod's owner UID")
	}

	log.WithField("uid", ownerUID).Info("retrieved owner UID successfully")

	log.Info("Creating cert upgrade job")
	if err := CreatePostSyncJob(ctx, client, namespace, ownerUID); err != nil {
		return errors.Wrap(err, "failed to create post sync job")
	}

	log.Info("Completed")
	return nil
}
