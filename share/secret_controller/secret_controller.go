package secretcontroller

import (
	"context"
	"errors"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
)

type ClusterDataCRDSpec struct {
	OldCA string `json:"oldca"`
	NewCA string `json:"newca"`

	ExpectedNodeNum int `json:"expected_node_num"`
}

type ClusterConsulNodeStatus struct {
	Stage       string
	LastChanged string
	Reason      string
}

type ClusterDataCRDStatus struct {
	Nodes  map[string]ClusterConsulNodeStatus
	Status map[string]string
}

type ClusterDataCRD struct {
	Spec       ClusterDataCRDSpec
	Status     ClusterDataCRDStatus
	Revision   int
	NodeNumber int // How many nodes are there in the consul cluster.
}

func (c *ClusterDataCRD) DeepCopy() *ClusterDataCRD {
	ret := ClusterDataCRD{
		Spec: c.Spec,
		Status: ClusterDataCRDStatus{
			Nodes:  map[string]ClusterConsulNodeStatus{},
			Status: map[string]string{},
		},
		Revision:   c.Revision,
		NodeNumber: c.NodeNumber,
	}
	for k, v := range c.Status.Nodes {
		ret.Status.Nodes[k] = v
	}
	for k, v := range c.Status.Status {
		ret.Status.Status[k] = v
	}
	return &ret
}

var ConflictError = errors.New("Data conflict.  Make sure you update revision.")

type SynchronizedStorageAccess interface {
	// Initialize
	Init(args map[string]string) error

	// Watch the storage for update.
	Watch(ctx context.Context, args map[string]string) (ClusterDataCRD, error)

	// Get the synchronized state.
	GetSynchronizedState(ctx context.Context, args map[string]string) (*ClusterDataCRD, error)

	// Set the synchronized state.
	SetSynchronizedState(ctx context.Context, crd *ClusterDataCRD) error

	// For k8s, we have to use a separate storage to store secrets, since most of time only Secrets are encrypted.

	// Get data from secret store.
	GetSecret(ctx context.Context, key string) (map[string]string, error)

	// Set data from secret store.
	SetSecret(ctx context.Context, key string, data map[string]string) error

	// For testing only
	RegisterCallback(ctx context.Context, callback func(string, interface{}) error) error

	Exit() error
}

/*
type KubernetesSecret struct {
	client *k8s.Client
}

func (k *KubernetesSecret) Init(args map[string]string) error {
	var err error
	k.client, err = k8s.NewInClusterClient()
	if err != nil {
		return errors.Wrap(err, "failed to create k8s client")
	}
	return nil
}

// Neuvector still uses Golang 1.14 due to the internal certificate issue, which makes client-go not usable.
// We should revisit later once this internal certificate issue is resolved.
func (k *KubernetesSecret) Watch(ctx context.Context, args map[string]string, callback func(*ClusterDataCRD) error) error {
	if k.client == nil {
		return errors.New("client is not initialized")
	}
	namespace, ok := args["namespace"]
	if !ok {
		return errors.New("namespace is not specified")
	}

	resourceName, ok := args["resourceName"]
	if !ok {
		return errors.New("resourceName is not specified")
	}

	// TODO: change to CRD.
	var secret corev1.Secret
	watcher, err := k.client.Watch(ctx, namespace, &secret)
	if err != nil {
		return errors.Wrap(err, "failed to create k8s watcher")
	}
	defer watcher.Close()

	evt, err := watcher.Next(&secret)
	if err != nil {
		return errors.Wrap(err, "failed to get next object")
	}

	if *secret.Metadata.Name != resourceName {
		return nil
	}

	l := lru.New(16)
	switch evt {
	case "ADDED", "MODIFIED":
		l.Add(secret.Metadata.Name, secret)
		if err := callback(&secret); err != nil {
			return err
		}
	case "DELETED":
		// We don't care about deleted
	}
	return nil
}
*/

// For testing
type LocalMemorySynchronizedStorage struct {
	cond    *sync.Cond
	crd     *ClusterDataCRD
	mutex   sync.RWMutex
	exit    bool
	secrets map[string]map[string]string

	// For testing
	callback func(string, interface{}) error
}

func NewLocalMemoryWatcher() SynchronizedStorageAccess {
	return &LocalMemorySynchronizedStorage{}
}

func NewClusterDataCRD() *ClusterDataCRD {
	return &ClusterDataCRD{
		Spec: ClusterDataCRDSpec{},
		Status: ClusterDataCRDStatus{
			Nodes:  map[string]ClusterConsulNodeStatus{},
			Status: map[string]string{},
		},
		Revision: 0,
	}
}

func (l *LocalMemorySynchronizedStorage) Init(args map[string]string) error {
	l.cond = sync.NewCond(&sync.Mutex{})
	l.crd = NewClusterDataCRD()
	go func() {
		for !l.exit {
			time.Sleep(time.Second * 5)
			l.cond.Broadcast()
		}
	}()
	return nil
}

func (l *LocalMemorySynchronizedStorage) Watch(ctx context.Context, args map[string]string) (ClusterDataCRD, error) {
	var ret ClusterDataCRD
	l.cond.L.Lock()
	l.cond.Wait()
	l.mutex.RLock()
	ret = *l.crd
	l.mutex.RUnlock()
	l.cond.L.Unlock()
	return ret, nil
}

func (l *LocalMemorySynchronizedStorage) GetSynchronizedState(ctx context.Context, args map[string]string) (*ClusterDataCRD, error) {
	var ret *ClusterDataCRD
	l.mutex.RLock()
	ret = l.crd.DeepCopy()
	l.mutex.RUnlock()
	return ret, nil
}

func (l *LocalMemorySynchronizedStorage) SetSynchronizedState(ctx context.Context, crd *ClusterDataCRD) error {
	l.mutex.Lock()
	defer l.mutex.Unlock()

	if l.crd.Revision != crd.Revision {
		return ConflictError
	}
	log.WithFields(log.Fields{
		"revision": l.crd.Revision,
		"nodes":    l.crd.Status.Nodes,
	}).Info("setting up state")
	l.crd = crd.DeepCopy()

	l.crd.Revision++
	if l.callback != nil {
		l.callback("NEW_STATE", l)
	}
	l.cond.Broadcast()

	return nil
}

func (l *LocalMemorySynchronizedStorage) GetSecret(ctx context.Context, key string) (map[string]string, error) {
	// Not thread safe.
	return l.secrets[key], nil
}

func (l *LocalMemorySynchronizedStorage) SetSecret(ctx context.Context, key string, data map[string]string) error {
	// Not thread safe.
	if l.secrets == nil {
		l.secrets = make(map[string]map[string]string)
	}
	l.secrets[key] = data
	return nil
}

func (l *LocalMemorySynchronizedStorage) RegisterCallback(ctx context.Context, callback func(string, interface{}) error) error {
	l.callback = callback
	return nil
}

func (l *LocalMemorySynchronizedStorage) Exit() error {
	l.exit = true
	l.cond.Broadcast()
	return nil
}
