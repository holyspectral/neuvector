package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"flag"

	"github.com/neuvector/neuvector/controller/kv"
	"github.com/pkg/errors"
	corev1 "k8s.io/api/core/v1"
	k8sError "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
)

func ResourceExists(ctx context.Context, client dynamic.Interface, resource schema.GroupVersionResource, name string) (bool, error) {
	_, err := client.Resource(resource).Namespace(*namespace).Get(ctx, name, metav1.GetOptions{})
	if err == nil {
		return true, nil
	}
	if k8sError.IsNotFound(err) {
		return false, nil
	} else {
		return false, err
	}
}

// This function checks if any resource listed exists or not.
func FindAnyRequiredResource(ctx context.Context, client dynamic.Interface) (bool, error) {
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
		exists, err := ResourceExists(ctx, client, v.resource, v.name)
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
func InitializeInternalSecret(ctx context.Context, client dynamic.Interface) error {

	found, err := FindAnyRequiredResource(ctx, client)
	if err != nil {
		return errors.Wrap(err, "failed to find existing resources")
	}

	// TODO: Move kv to share.
	// TODO: Use template.
	cacert, cakey, err := kv.GenerateCAWithRSAKey(nil, *rsaKeySize)
	if err != nil {
		return errors.Wrap(err, "failed to generate ca cert")
	}
	capair, err := tls.X509KeyPair(cacert, cakey)
	if err != nil {
		return errors.Wrap(err, "failed to load ca key pair")
	}

	ca, err := x509.ParseCertificate(capair.Certificate[0])
	if err != nil {
		return errors.Wrap(err, "failed to parse ca cert")
	}
	// TODO: Use template
	cert, key, err := kv.GenerateTLSCertWithRSAKey(nil, *rsaKeySize, ca, capair.PrivateKey)
	if err != nil {
		return errors.Wrap(err, "failed to generate TLS certificate")
	}

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

	if !found {
		// Fresh install
		secret.Name = *dstSecretName
		if _, err := ApplyK8sSecret(ctx, client, secret); err != nil {
			return errors.Wrap(err, "failed to write dst secret")
		}
		secret.Name = *activeSecretName
		if _, err := ApplyK8sSecret(ctx, client, secret); err != nil {
			return errors.Wrap(err, "failed to write active secret")
		}

		return nil
	}
	// Upgrade
	secret.Name = *srcSecretName
	if _, err := ApplyK8sSecret(ctx, client, secret); err != nil {
		return errors.Wrap(err, "failed to write src secret")
	}
	return nil

}

func PreSyncHook() error {
	flag.Parse()

	client, err := NewK8sClient(*kubeconfig)
	if err != nil {
		return errors.Wrap(err, "failed to create k8s client")
	}
	if err := InitializeInternalSecret(context.Background(), client); err != nil {
		return errors.Wrap(err, "failed to initialize internal secret")
	}
	return nil
}
