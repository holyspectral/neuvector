package migration

import (
	"fmt"
	"io/ioutil"
	"path"
	"time"

	"github.com/neuvector/neuvector/share/cluster"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	v1 "k8s.io/api/core/v1"
	"k8s.io/client-go/informers"
	coreinformers "k8s.io/client-go/informers/core/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/clientcmd"
)

type InternalSecretController struct {
	informerFactory informers.SharedInformerFactory
	secretInformer  coreinformers.SecretInformer
	namespace       string
	secretName      string
	lastRevision    string
	reloadFuncs     []func([]byte, []byte, []byte) error
}

func ReloadCert(cacert []byte, cert []byte, key []byte) error {
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

	for _, f := range c.reloadFuncs {
		err := f(cacert, cert, key)
		if err != nil {
			log.WithError(err).Error("failed to reload internal certs")
		}
	}
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

func (c *InternalSecretController) Run(stopCh chan struct{}) error {
	// Starts all the shared informers that have been created by the factory so
	// far.
	c.informerFactory.Start(stopCh)
	// wait for the initial synchronization of the local cache.
	if !cache.WaitForCacheSync(stopCh, c.secretInformer.Informer().HasSynced) {
		return fmt.Errorf("failed to sync")
	}
	return nil
}

func (c *InternalSecretController) secretAdd(obj interface{}) {
	secret := obj.(*v1.Secret)
	if !c.IsOfInterest(secret) {
		return
	}
	// TODO: FIXME
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

	// TODO: FIXME
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
	// TODO: FIXME
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

	secretInformer.Informer().AddEventHandler(
		cache.ResourceEventHandlerFuncs{
			// Called on creation
			AddFunc: c.secretAdd,
			// Called on resource update and every resyncPeriod on existing resources.
			UpdateFunc: c.secretUpdate,
			// Called on resource deletion.
			DeleteFunc: c.secretDelete,
		},
	)

	return c, nil
}

func InitializeInternalSecretController(reloadFuncs []func([]byte, []byte, []byte) error) error {
	config, err := clientcmd.BuildConfigFromFlags("", "/home/sam/.kube/config")
	if err != nil {
		panic(err.Error())
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return fmt.Errorf("failed to get k8s config: %w", err)
	}

	factory := informers.NewSharedInformerFactory(clientset, time.Hour*24)

	// TODO: Not hardcode these
	controller, err := NewInternalSecretController(factory, "neuvector", "neuvector-internal-certs", reloadFuncs)
	if err != nil {
		return fmt.Errorf("failed to create internal secret controller: %w", err)
	}

	stop := make(chan struct{})
	defer close(stop)
	err = controller.Run(stop)
	if err != nil {
		return fmt.Errorf("failed to run internal secret controller: %w", err)
	}

	// TODO: Wait until the first.
	log.Info("cache is synced and internal cert is ready")

	return nil
}
