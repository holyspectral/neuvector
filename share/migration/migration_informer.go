package migration

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"path"
	"reflect"
	"time"

	"errors"

	"github.com/neuvector/neuvector/share/cluster"
	"github.com/neuvector/neuvector/share/healthz"
	log "github.com/sirupsen/logrus"
	v1 "k8s.io/api/core/v1"
	"k8s.io/client-go/informers"
	coreinformers "k8s.io/client-go/informers/core/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
)

const WaitSyncTimeout = time.Minute * 5

type InternalSecretController struct {
	informerFactory informers.SharedInformerFactory
	secretInformer  coreinformers.SecretInformer
	namespace       string
	secretName      string
	lastRevision    string
	reloadFuncs     []func([]byte, []byte, []byte) error
	initialized     bool
}

func verifyCert(cacert []byte, cert []byte, key []byte) error {

	roots := x509.NewCertPool()
	ok := roots.AppendCertsFromPEM(cacert)
	if !ok {
		return errors.New("failed to append cert")
	}

	block, _ := pem.Decode(cert)
	if block == nil {
		return errors.New("failed to decode cert")
	}
	crt, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse certificate: %w", err)
	}

	opts := x509.VerifyOptions{
		Roots:         roots,
		DNSName:       cluster.InternalCertCN,
		Intermediates: x509.NewCertPool(),
	}

	if _, err := crt.Verify(opts); err != nil {
		return fmt.Errorf("failed to verify certificate: %w", err)
	}

	if _, err := tls.X509KeyPair(cert, key); err != nil {
		return fmt.Errorf("invalid key cert pair: %w", err)
	}
	return nil
}

func ReloadCert(cacert []byte, cert []byte, key []byte) error {
	if err := verifyCert(cacert, cert, key); err != nil {
		return fmt.Errorf("invalid key/cert: %w", err)
	}

	if err := ioutil.WriteFile(path.Join(cluster.InternalCertDir, cluster.InternalCACert), []byte(cacert), 0600); err != nil {
		return fmt.Errorf("failed to write cacert: %w", err)
	}
	if err := ioutil.WriteFile(path.Join(cluster.InternalCertDir, cluster.InternalCert), []byte(cert), 0600); err != nil {
		return fmt.Errorf("failed to write cert: %w", err)
	}
	if err := ioutil.WriteFile(path.Join(cluster.InternalCertDir, cluster.InternalCertKey), []byte(key), 0600); err != nil {
		return fmt.Errorf("failed to write key: %w", err)
	}
	return nil
}

// TODO: Make sure that main thread can wait until informer gets its secret.
func (c *InternalSecretController) ReloadSecret(secret *v1.Secret) error {
	cacert := secret.Data[ACTIVE_SECRET_PREFIX+CACERT_FILENAME]
	cert := secret.Data[ACTIVE_SECRET_PREFIX+CERT_FILENAME]
	key := secret.Data[ACTIVE_SECRET_PREFIX+KEY_FILENAME]

	if cacert == nil || cert == nil || key == nil {
		return errors.New("active secret is not found")
	}

	if err := ReloadCert(cacert, cert, key); err != nil {
		return fmt.Errorf("failed to reload certs: %w", err)
	}

	// Skip the first round since secret is loaded.
	if !c.initialized {
		c.initialized = true
		healthz.UpdateStatus("cert.revision", secret.ResourceVersion)
		return nil
	}

	for _, f := range c.reloadFuncs {
		err := f(cacert, cert, key)
		if err != nil {
			log.WithError(err).Error("failed to reload internal certs")
		}
	}
	healthz.UpdateStatus("cert.revision", secret.ResourceVersion)
	return nil
}

func (c *InternalSecretController) IsOfInterest(secret *v1.Secret) bool {
	if secret.Namespace != c.namespace || secret.Name != c.secretName {
		return false
	}
	if secret.ResourceVersion == c.lastRevision {
		// The same revision as last time.
		return false
	}
	return true
}

func (c *InternalSecretController) Run(stopCh <-chan struct{}) error {
	c.informerFactory.Start(stopCh)

	ctx, cancel := context.WithTimeout(context.Background(), WaitSyncTimeout)
	defer cancel()
	// wait for the initial synchronization of the local cache.
	if !cache.WaitForCacheSync(ctx.Done(), func() bool {
		if !c.secretInformer.Informer().HasSynced() {
			return false
		}
		return c.initialized
	}) {
		return errors.New("failed to sync with k8s for internal certs")
	}
	return nil
}

func (c *InternalSecretController) secretAdd(obj interface{}) {
	secret := obj.(*v1.Secret)
	if !c.IsOfInterest(secret) {
		return
	}
	log.Info("internal secret is created: ", secret.Namespace, secret.Name)
	if err := c.ReloadSecret(secret); err != nil {
		log.WithError(err).Error("failed to reload secret")
	}
}

func (c *InternalSecretController) secretUpdate(old, new interface{}) {
	oldSecret := old.(*v1.Secret)
	newSecret := new.(*v1.Secret)

	if !c.IsOfInterest(oldSecret) {
		return
	}

	// Check if old secret is the same with new secret.
	// Note: There is no guarantee that oldSecret will be available, but for checking it's enough.
	if reflect.DeepEqual(oldSecret.Data[ACTIVE_SECRET_PREFIX+CACERT_FILENAME], newSecret.Data[ACTIVE_SECRET_PREFIX+CACERT_FILENAME]) &&
		reflect.DeepEqual(oldSecret.Data[ACTIVE_SECRET_PREFIX+CERT_FILENAME], newSecret.Data[ACTIVE_SECRET_PREFIX+CERT_FILENAME]) &&
		reflect.DeepEqual(oldSecret.Data[ACTIVE_SECRET_PREFIX+KEY_FILENAME], newSecret.Data[ACTIVE_SECRET_PREFIX+KEY_FILENAME]) {

		// The secret is the same.  We don't have to do anything.
		return
	}

	log.Info("internal secret is updated: ", newSecret.Namespace, newSecret.Name)
	if err := c.ReloadSecret(newSecret); err != nil {
		log.WithError(err).Error("failed to reload secret")
	}
}

func (c *InternalSecretController) secretDelete(obj interface{}) {
	secret := obj.(*v1.Secret)
	if !c.IsOfInterest(secret) {
		return
	}
	log.Info("internal secret is deleted", secret.Namespace, secret.Name)
}

func NewInternalSecretController(informerFactory informers.SharedInformerFactory, namespace string, secretName string, reloadFuncs []func([]byte, []byte, []byte) error) (*InternalSecretController, error) {
	secretInformer := informerFactory.Core().V1().Secrets()

	c := &InternalSecretController{
		informerFactory: informerFactory,
		secretInformer:  secretInformer,
		namespace:       namespace,
		secretName:      secretName,
		reloadFuncs:     reloadFuncs,
	}

	secretInformer.Informer().AddEventHandlerWithResyncPeriod(
		cache.ResourceEventHandlerFuncs{
			// Called on creation
			AddFunc: c.secretAdd,
			// Called on resource update and every resyncPeriod on existing resources.
			UpdateFunc: c.secretUpdate,
			// Called on resource deletion.
			DeleteFunc: c.secretDelete,
		},
		time.Minute*30,
	)

	return c, nil
}

func InitializeInternalSecretController(ctx context.Context, reloadFuncs []func([]byte, []byte, []byte) error) error {
	var err error
	var config *rest.Config
	config, err = rest.InClusterConfig()
	if err != nil {
		return fmt.Errorf("failed to read in-cluster config: %w", err)
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return fmt.Errorf("failed to get k8s config: %w", err)
	}

	factory := informers.NewSharedInformerFactoryWithOptions(clientset, time.Hour*24, informers.WithNamespace("neuvector"))

	// TODO: Not hardcode these
	controller, err := NewInternalSecretController(factory, "neuvector", "neuvector-internal-certs", reloadFuncs)
	if err != nil {
		return fmt.Errorf("failed to create internal secret controller: %w", err)
	}

	err = controller.Run(ctx.Done())
	if err != nil {
		return fmt.Errorf("failed to run internal secret controller: %w", err)
	}

	// TODO: Wait until the first.
	log.Info("cache is synced and internal cert is ready")

	return nil
}
