package secretcontroller

import (
	"context"
	"errors"
	"sync"
	"time"
)

// nodeid => status + global status
type ClusterDataCRD struct {
	Spec     map[string]string
	Status   map[string]string
	Revision int
}

type CentralDatabaseAccess interface {
	Init(args map[string]string) error
	Watch(ctx context.Context, args map[string]string) (ClusterDataCRD, error)
	GetCRD(ctx context.Context, args map[string]string) (ClusterDataCRD, error)
	SetState(ctx context.Context, crd *ClusterDataCRD) error
	GetSecret(ctx context.Context, key string) (map[string]string, error)
	SetSecret(ctx context.Context, key string, data map[string]string) error
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
type LocalMemory struct {
	cond    *sync.Cond
	crd     *ClusterDataCRD
	mutex   sync.RWMutex
	exit    bool
	secrets map[string]map[string]string
}

func NewLocalMemoryWatcher() CentralDatabaseAccess {
	return &LocalMemory{}
}

func NewClusterDataCRD() *ClusterDataCRD {
	return &ClusterDataCRD{
		Spec:     map[string]string{},
		Status:   map[string]string{},
		Revision: 0,
	}
}

func (l *LocalMemory) Init(args map[string]string) error {
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

func (l *LocalMemory) Watch(ctx context.Context, args map[string]string) (ClusterDataCRD, error) {
	var ret ClusterDataCRD
	l.cond.L.Lock()
	l.cond.Wait()
	l.mutex.RLock()
	ret = *l.crd
	l.mutex.RUnlock()
	l.cond.L.Unlock()
	return ret, nil
}

func (l *LocalMemory) GetCRD(ctx context.Context, args map[string]string) (ClusterDataCRD, error) {
	var ret ClusterDataCRD
	l.mutex.RLock()
	ret = *l.crd
	l.mutex.RUnlock()
	return ret, nil
}

func (l *LocalMemory) SetState(ctx context.Context, crd *ClusterDataCRD) error {
	l.mutex.Lock()
	defer l.mutex.Unlock()

	if l.crd.Revision != *&crd.Revision {
		return errors.New("conflict")
	}

	l.crd = crd
	l.crd.Revision++
	l.cond.Broadcast()

	return nil
}

func (l *LocalMemory) GetSecret(ctx context.Context, key string) (map[string]string, error) {
	// Not thread safe.
	return l.secrets[key], nil
}

func (l *LocalMemory) SetSecret(ctx context.Context, key string, data map[string]string) error {
	// Not thread safe.
	l.secrets[key] = data
	return nil
}

func (l *LocalMemory) Exit() error {
	l.exit = true
	l.cond.Broadcast()
	return nil
}
