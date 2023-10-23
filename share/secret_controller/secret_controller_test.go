package secretcontroller

import (
	"context"
	"fmt"
	"math"
	"strconv"
	"testing"
	"time"

	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"

	log "github.com/sirupsen/logrus"
	"k8s.io/apimachinery/pkg/util/wait"
)

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
			watcher.SetState(context.TODO(), &ClusterDataCRD{
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

type InternalCA interface {
	// Return cacert, cert, key.
	GetInternalCerts() (string, string, string, error)
	ApplyInternalCerts(cacert string, cert string, key string) error
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

func NewTestInternalCAProvider() InternalCA {
	return &TestInternalCAProvider{}
}

var DefaultBackOff = wait.Backoff{
	Steps:    10,
	Duration: 10 * time.Millisecond,
	Factor:   1.0,
	Jitter:   0.1,
}

// TODO: support recoverable errors.
func RetryOnConflict(backoff wait.Backoff, fn func() error) error {
	return wait.ExponentialBackoff(backoff, func() (bool, error) {
		err := fn()
		if err != nil {
			// TODO: Fix this
			log.WithError(err).Warn("failed to handle event")
			//return false, err
			return false, nil
		}
		return true, nil
	})
}

const (
	InternalCertStatusFailed      = "failed"
	InternalCertStatusUndefined   = ""
	InternalCertStatusMergedCA    = "merged-ca"
	InternalCertStatusMergedCAKey = "merged-ca-new-key"
	InternalCertStatusNewCAKey    = "new-ca-new-key"
)

var InternalCertMap = map[string]int{
	InternalCertStatusFailed:      -1, // TODO: need extra handling
	InternalCertStatusUndefined:   0,
	InternalCertStatusMergedCA:    1,
	InternalCertStatusMergedCAKey: 2,
	InternalCertStatusNewCAKey:    3,
}

const InternalCertStatusMaxState = 4

// TODO: Need more testing.
func ShouldWaitForOtherNodes(nodeNum int, currentStatus string, nodeStatus map[string]ClusterConsulNodeStatus) (bool, error) {
	if len(nodeStatus) < nodeNum && currentStatus != InternalCertStatusUndefined {
		// Some nodes didn't report yet.  Do not move to next stage that soon.
		return true, nil
	}
	currentStatusID := InternalCertMap[currentStatus]
	faster := false
	for _, v := range nodeStatus {
		if v.Stage == InternalCertStatusFailed {
			return false, errors.New("Other node has failed.  This node should not continue.")
		}
		nodeStatusID := InternalCertMap[v.Stage]
		if currentStatusID > nodeStatusID {
			// This node is faster than others.  Don't have to do anything for now.
			faster = true
		}
		diff := (InternalCertStatusMaxState + nodeStatusID - currentStatusID) % InternalCertStatusMaxState
		if nodeStatusID != 0 && currentStatusID != 0 && math.Abs(float64(diff)) > 1 {
			// Something is wrong. One node moves too fast.
			return false, fmt.Errorf("invalid status: current: %v, node: %v, diff: %v", currentStatusID, nodeStatusID, diff)
		}
	}
	return faster, nil
}

func TestUpgrade(t *testing.T) {
	// Setup test provider
	watcher := NewLocalMemoryWatcher()
	watcher.Init(nil)

	internalca := NewTestInternalCAProvider()

	// TODO: How to deal with restart and after failure?
	//       The point is that we don't know how many nodes will be there.  Race condition?
	//       The one triggered the flow should specify "how many nodes are expected".
	//       TODO: What if the number is changed?
	//             If #node decreases, it should time out.
	//             If #node increases, it should detect that and fail the migration.
	// TODO: Figure out what would happen when consul nodes++ without changing node number in command line argument.
	consul_node_reconcile := func(name string) {
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
			_, err := watcher.Watch(context.TODO(), nil)
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
				crd, err := watcher.GetCRD(context.TODO(), nil)
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

				oldsecret, err := watcher.GetSecret(context.TODO(), crd.Spec.OldCA)
				if err != nil {
					return errors.Wrap(err, "failed to get new cacert.  Nothing to do.")
				}
				oldcacert = oldsecret["cacert"]
				oldcert = oldsecret["cert"]
				oldkey = oldsecret["key"]
				//oldchecksum = oldsecret["sha256sum"]

				newsecret, err := watcher.GetSecret(context.TODO(), crd.Spec.NewCA)
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
					// Keep in this state.
					expectedCAcert = newcacert
					expectedCert = newcert
					expectedKey = newkey
					nextstage = InternalCertStatusNewCAKey
				case InternalCertStatusFailed:
					nextstage = InternalCertStatusFailed
					// Should rollback to the original certs
				}

				if err := internalca.ApplyInternalCerts(expectedCAcert, expectedCert, expectedKey); err != nil {
					return err
				}

				// Nothing changed. See you next round.
				crd.Status.Nodes[name] = ClusterConsulNodeStatus{
					Stage:       nextstage,
					LastChanged: time.Now().Format(time.RFC3339),
				}
				if err := watcher.SetState(context.TODO(), crd); err != nil {
					return err
				}
				return nil
			})
			if err != nil {
				log.WithError(err).Error("Failed to handle events. Mark this node as failed.")
				if err := RetryOnConflict(DefaultBackOff, func() error {
					// TODO: Should it be kept in retry logic?
					if err := internalca.ApplyInternalCerts(oldcacert, oldcert, oldkey); err != nil {
						return err
					}
					crd, err := watcher.GetCRD(context.TODO(), nil)
					if err != nil {
						return err
					}
					crd.Status.Nodes[name] = ClusterConsulNodeStatus{
						Stage:       InternalCertStatusFailed,
						LastChanged: time.Now().Format(time.RFC3339),
					}
					if err := watcher.SetState(context.TODO(), crd); err != nil {
						return err
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
		//internalca.ApplyInternalCerts("oldca")
		watcher.SetState(context.TODO(), &ClusterDataCRD{
			Spec: ClusterDataCRDSpec{NewCA: "newca", OldCA: "oldca"},
			Status: ClusterDataCRDStatus{
				Nodes:  map[string]ClusterConsulNodeStatus{},
				Status: map[string]string{},
			},
			Revision:   0,
			NodeNumber: 3,
		})
	}

	modifyca()
	go consul_node_reconcile("NodeA")
	go consul_node_reconcile("NodeB")
	go consul_node_reconcile("NodeC")
	time.Sleep(time.Second * 5)

	crd, err := watcher.GetCRD(context.TODO(), nil)

	assert.Nil(t, err)
	for _, v := range crd.Status.Nodes {
		assert.Equal(t, InternalCertStatusNewCAKey, v.Stage)
	}

	watcher.Exit()

	return
}
