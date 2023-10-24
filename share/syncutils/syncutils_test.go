package syncutils

import (
	"context"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/pkg/errors"
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

	// NOTE: To deal with restart and after failure?
	//       The point is that we don't know how many nodes will be there.  Race condition?
	//       The one triggered the flow should specify "how many nodes are expected".
	//       TODO: What if the number is changed?
	//             If #node decreases, it should time out.
	//             If #node increases, it should detect that and fail the migration.
	// TODO: Figure out what would happen when consul nodes++ without changing node number in command line argument.
	consul_node_reconcile := func(name string, ss SynchronizedStorageAccess, certProvider InternalCertProvider) {
		// TODO: When joining, we have to register myself as one node inside CRD.
		// Use case: New node joining when doing certificate update.
		// Those nodes will detect one of nodes is in a wrong state should fail the flow.
		// TODO: What if a new node is added when all nodes are marked as successful?
		//       When it registers itself, new node should know that all nodes are already successful.
		//       When old pods writing status, it should notice that too.
		for {
			// 1. Get notification.  The watcher should return when:
			//   a. Change happens in the resource.
			//   b. Resync period reached
			//   c. Context timed out.
			_, err := ss.Watch(context.TODO(), nil)
			if err != nil {
				log.WithError(err).Error(err)
				continue
			}

			var oldcacert, oldcert, oldkey string
			var newcacert, newcert, newkey string
			//var oldchecksum, newchecksum string

			// Note: If RetryOnConflict returns error, we should mark this node as failure.
			// TODO: If we see a node in failure mode, roll back.
			err = RetryOnConflict(DefaultBackOff, func() error {
				crd, err := ss.GetSynchronizedState(context.TODO(), nil)
				if err != nil {
					return err
				}

				//
				// 1. Check if this node goes faster than others.
				//    This function will make sure that all nodes are in the same state until they start next stage of migration.
				//    This function should also report error when other nodes failed.
				shouldWait, err := ShouldWaitForOtherNodes(crd.NodeNumber, crd.Status.Nodes[name].Stage, crd.Status.Nodes)
				if err != nil {
					return errors.Wrap(err, "something is wrong in the state machine. Give up and rollback")
				}

				if shouldWait {
					return nil
				}

				//
				// 2. Get old secrets and new secrets.
				//
				if crd.Spec.NewCA == "" {
					log.Debug("No new certificate is specified.  Nothing to do.")
					return nil
				}

				if crd.Spec.OldCA == "" {
					// TODO: Mirgrate from built-in certs.
					log.Debug("No new certificate is specified.  Nothing to do.")
					return nil
				}

				oldsecret, err := ss.GetSecret(context.TODO(), crd.Spec.OldCA)
				if err != nil {
					return errors.Wrap(err, "failed to get new cacert.  Nothing to do.")
				}
				oldcacert = oldsecret["cacert"]
				oldcert = oldsecret["cert"]
				oldkey = oldsecret["key"]
				//oldchecksum = oldsecret["sha256sum"]

				newsecret, err := ss.GetSecret(context.TODO(), crd.Spec.NewCA)
				if err != nil {
					return errors.Wrap(err, "failed to get new cacert.  Nothing to do.")
				}
				newcacert = newsecret["cacert"]
				newcert = newsecret["cert"]
				newkey = newsecret["key"]
				//newchecksum = newsecret["sha256sum"]

				// 3. Generate expected certs for the given stage.
				var nextstage string
				var expectedCAcert string
				var expectedCert string
				var expectedKey string

				// InternalCertStatusOk          = "ok"
				// InternalCertStatusMergedCA    = "merged-ca"
				// InternalCertStatusMergedCAKey = "merged-ca-new-key"
				// InternalCertStatusNewCAKey    = "new-ca-new-key"
				switch crd.Status.Nodes[name].Stage {
				case InternalCertStatusUndefined:
					// Check CRD and if there is new, use merged CA.
					// TODO: Move the checking logic to apply().
					/*
						h := sha256.New()
						data := fmt.Sprintf("%s_%s_%s", newsecret["cacert"], newsecret["cert"], newsecret["key"])
						h.Write([]byte(data))
						if fmt.Sprintf("%x\n", h.Sum(nil)) != newsecret["sha256sum"] {
							return errors.New("Invalid certs.  Secrets are updated afterwards?")
						}
					*/
					// TODO: Revisit to see if mergedCA is cross platform.
					expectedCAcert = oldcacert + "\n" + newcacert
					expectedCert = oldcert
					expectedKey = oldkey
					nextstage = InternalCertStatusMergedCA

				case InternalCertStatusMergedCA:
					// Once everyone is in this stage, use merged CA + new key.
					expectedCAcert = oldcacert + "\n" + newcacert
					expectedCert = newcert
					expectedKey = newkey
					nextstage = InternalCertStatusMergedCAKey
				case InternalCertStatusMergedCAKey:
					// Once everyone is in this stage, use new CA + new key.
					expectedCAcert = newcacert
					expectedCert = newcert
					expectedKey = newkey
					nextstage = InternalCertStatusNewCAKey
				case InternalCertStatusNewCAKey:
					// Move to success.
					expectedCAcert = newcacert
					expectedCert = newcert
					expectedKey = newkey
					nextstage = InternalCertStatusSuccess
				case InternalCertStatusFailed:
					nextstage = InternalCertStatusFailed
					// Should rollback to the original certs
				}

				if err := certProvider.ApplyInternalCerts(expectedCAcert, expectedCert, expectedKey); err != nil {
					return err
				}

				// Nothing changed. See you next round.
				crd.Status.Nodes[name] = ClusterConsulNodeStatus{
					Stage:       nextstage,
					LastChanged: time.Now().Format(time.RFC3339),
				}
				if err := ss.SetSynchronizedState(context.TODO(), crd); err != nil {
					return err
				}
				return nil
			})
			if err != nil {
				log.WithError(err).Error("Failed to handle events. Mark this node as failed.")
				orig_error := err
				if err := RetryOnConflict(DefaultBackOff, func() error {
					// TODO: Should it be kept in retry logic?
					if err := certProvider.ApplyInternalCerts(oldcacert, oldcert, oldkey); err != nil {
						return err
					}
					crd, err := ss.GetSynchronizedState(context.TODO(), nil)
					if err != nil {
						return err
					}
					status := crd.Status.Nodes[name]
					if status.Stage != InternalCertStatusFailed {
						crd.Status.Nodes[name] = ClusterConsulNodeStatus{
							Stage:       InternalCertStatusFailed,
							LastChanged: time.Now().Format(time.RFC3339),
							Reason:      orig_error.Error(),
						}
						if err := ss.SetSynchronizedState(context.TODO(), crd); err != nil {
							return err
						}
					}

					return nil
				}); err != nil {
					// Serious errors here and probably something with the shared storage. Nothing we can do.
					log.WithError(err).Error("failed to update CRD.")
				}
			}
		}
	}

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
	go consul_node_reconcile("NodeA", watcher, NewTestInternalCAProvider())
	go consul_node_reconcile("NodeB", watcher, NewTestInternalCAProvider())
	go consul_node_reconcile("NodeC", watcher, NewTestInternalCAProvider())

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
