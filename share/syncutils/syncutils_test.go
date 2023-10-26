package syncutils

import (
	"context"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	log "github.com/sirupsen/logrus"
)

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

func TestLocalMemoryWatcher(t *testing.T) {
	watcher := NewLocalMemoryWatcher()
	watcher.Init(nil)

	var exit bool

	reader := func(name string) {
		for !exit {
			crd, _ := watcher.Watch(context.TODO(), nil)
			t.Log(name, crd)
		}
	}

	writer := func() {
		for i := 0; i < 5; i++ {
			watcher.SetSynchronizedState(context.TODO(), &ClusterDataCRD{
				Status: ClusterDataCRDStatus{
					Status: map[string]string{
						"number": strconv.Itoa(i),
					},
				},
			})
			time.Sleep(time.Second)
		}
	}

	go reader("A")
	go reader("B")
	go reader("C")
	writer()
	exit = true
	watcher.Exit()
	t.Log("completed")

	return
}

type TestInternalCAProvider struct {
	cacert string
	cert   string
	key    string
}

func (i *TestInternalCAProvider) GetInternalCerts() (string, string, string, error) {
	return i.cacert, i.cert, i.key, nil
}

func (i *TestInternalCAProvider) ApplyInternalCerts(cacert string, cert string, key string) error {
	// Should apply new certs, reload and wait until it's back to normal.
	// TODO: Make sure that cacert can accept cert and key.
	// TODO: Make sure cacert, cert and key are valid.
	i.cacert = cacert
	i.cert = cert
	i.key = key
	return nil
}

func NewTestInternalCAProvider() InternalCertProvider {
	return &TestInternalCAProvider{}
}

func TestUpgrade(t *testing.T) {
	// Setup test provider
	watcher := NewLocalMemoryWatcher()
	watcher.Init(nil)

	// Only newca is specified.
	modifyca := func() {
		watcher.SetSecret(context.TODO(), "newca", map[string]string{
			"cacert":    "newcacert",
			"cert":      "newcert",
			"key":       "newkey",
			"sha256sum": "d3a5258e95b39b9a375dcc25569914db019d11053f7430716e25521ba5c2607b",
		})
		//InternalCAProvider.ApplyInternalCerts("oldca")
		watcher.SetSynchronizedState(context.TODO(), &ClusterDataCRD{
			Spec: ClusterDataCRDSpec{NewCA: "newca", OldCA: "oldca"},
			Status: ClusterDataCRDStatus{
				Nodes:  map[string]ClusterConsulNodeStatus{},
				Status: map[string]string{},
			},
			Revision:   0,
			NodeNumber: 3,
		})
	}

	endChan := make(chan int)

	modifyca()
	watcher.RegisterCallback(context.TODO(), func(s string, ssa interface{}) error {
		lm, ok := ssa.(*LocalMemorySynchronizedStorage)
		assert.True(t, ok)
		log.WithField("state", s).Warning(lm.crd.Status.Nodes)

		notDoneYet := false
		for _, v := range lm.crd.Status.Nodes {
			assert.NotEqual(t, InternalCertStatusFailed, v.Stage)
			if v.Stage != InternalCertStatusSuccess {
				notDoneYet = true
			}
		}

		if !notDoneYet {
			// all success
			endChan <- 1
		}
		return nil
	})
	go MonitorInternalCertUpdate("NodeA", watcher, NewTestInternalCAProvider())
	go MonitorInternalCertUpdate("NodeB", watcher, NewTestInternalCAProvider())
	go MonitorInternalCertUpdate("NodeC", watcher, NewTestInternalCAProvider())

	crd, err := watcher.GetSynchronizedState(context.TODO(), nil)

	assert.Nil(t, err)
	for _, v := range crd.Status.Nodes {
		assert.Equal(t, InternalCertStatusNewCAKey, v.Stage)
	}

	select {
	case <-endChan:
	}

	watcher.Exit()

	return
}
