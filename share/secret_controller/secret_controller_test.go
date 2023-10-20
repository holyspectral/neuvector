package secretcontroller

import (
	"context"
	"crypto/sha256"
	"fmt"
	"math"
	"strconv"
	"testing"
	"time"

	"github.com/pkg/errors"

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
				Status: map[string]string{
					"number": strconv.Itoa(i),
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
	i.cacert = cacert
	i.cert = cert
	i.key = key
	return nil
}

func NewTestInternalCAProvider() InternalCA {
	return &TestInternalCAProvider{}
}

var DefaultBackOff = wait.Backoff{
	Steps:    5,
	Duration: 10 * time.Millisecond,
	Factor:   1.0,
	Jitter:   0.1,
}

// TODO: support recoverable errors.
func RetryOnConflict(backoff wait.Backoff, fn func() error) error {
	return wait.ExponentialBackoff(backoff, func() (bool, error) {
		err := fn()
		if err != nil {
			return false, err
		}
		return true, nil
	})
}

const (
	InternalCertStatusOk          = "ok"
	InternalCertStatusMergedCA    = "merged-ca"
	InternalCertStatusMergedCAKey = "merged-ca-new-key"
	InternalCertStatusNewCAKey    = "new-ca-new-key"
)

var InternalCertMap = map[string]int{
	InternalCertStatusOk:          0,
	InternalCertStatusMergedCA:    1,
	InternalCertStatusMergedCAKey: 2,
	InternalCertStatusNewCAKey:    3,
}

func ShouldWaitForOtherNodes(currentStatus string, nodeStatus map[string]string) (bool, error) {
	currentStatusID := InternalCertMap[currentStatus]
	faster := false
	for _, v := range nodeStatus {
		nodeStatusID := InternalCertMap[v]
		if currentStatusID > nodeStatusID {
			// This node is faster than others.  Don't have to do anything for now.
			faster = true
		}
		if nodeStatusID != 0 && currentStatusID != 0 && math.Abs(float64(nodeStatusID-currentStatusID)) > 1 {
			// Something is wrong. One node moves too fast.
			return false, fmt.Errorf("invalid status: current: %v, node: %v", currentStatusID, nodeStatusID)
		}
	}
	return faster, nil
}

func TestUpgrade(t *testing.T) {
	// Setup test provider
	watcher := NewLocalMemoryWatcher()

	watcher.SetSecret(context.TODO(), "oldca", map[string]string{
		"cacert": "oldcacert",
		"cert":   "oldcert",
		"key":    "oldkey",
	})

	watcher.SetState(context.TODO(), &ClusterDataCRD{
		Spec: map[string]string{},
	})

	internalca := NewTestInternalCAProvider()

	watcher.Init(nil)

	// stage1: "start" => (newca) => "mergedca"
	// stage2: "mergedca" => (newkey_deployed) => "mergedca_newkey"
	// stage3: "mergedca_newkey" => (oldca_removed) => "start"

	// TODO: How to get the current CA/key?
	consul_node_reconcile := func(name string) {
		// TODO: When joining, we have to register myself as one node inside CRD.
		// Use case: New node joining when doing certificate update.
		// Those nodes will detect one of nodes is in a wrong state should fail the flow.
		// TODO: What if a new node is added when all nodes are marked as successful?
		//       When it registers itself, new node should know that all nodes are already successful.
		//       When old pods writing status, it should notice that too.
		for {
			_, err := watcher.Watch(context.TODO(), nil)
			if err != nil {
				log.WithError(err).Error(err)
				continue
			}

			err = RetryOnConflict(DefaultBackOff, func() error {
				crd, err := watcher.GetCRD(context.TODO(), nil)
				if err != nil {
					return err
				}

				shouldWait, err := ShouldWaitForOtherNodes(crd.Status[name], crd.Status)
				if err != nil {
					return errors.Wrap(err, "something is wrong in the state machine. Give up and rollback.")
				}

				if shouldWait {
					return nil
				}

				// InternalCertStatusOk          = "ok"
				// InternalCertStatusMergedCA    = "merged-ca"
				// InternalCertStatusMergedCAKey = "merged-ca-new-key"
				// InternalCertStatusNewCAKey    = "new-ca-new-key"
				switch crd.Status[name] {
				case InternalCertStatusOk:
					// Check CRD and if there is new, use merged CA.
				case InternalCertStatusMergedCA:
					// Once everyone is in this stage, use merged CA + new key.
				case InternalCertStatusMergedCAKey:
					// Once everyone is in this stage, use new CA + new key.
				case InternalCertStatusNewCAKey:
					// Once everyone is in this stage, move to ok.
				}

				caname, ok := crd.Spec["newca"]
				if !ok {
					log.Debug("No new certificate is specified.  Nothing to do.")
					return nil
				}
				secret, err := watcher.GetSecret(context.TODO(), caname)
				if err != nil {
					return errors.Wrap(err, "failed to get new cacert.  Nothing to do.")
				}

				cacert, cert, key, err := internalca.GetInternalCerts()
				if err != nil {
					return errors.Wrap(err, "failed to get the current internal certs.  Nothing to do.")
				}

				if secret["cacert"] == "" || secret["cert"] == "" || secret["key"] == "" {
					return fmt.Errorf("Invalid certs: %v", secret)
				}

				h := sha256.New()
				data := fmt.Sprintf("%s_%s_%s", secret["cacert"], secret["cert"], secret["key"])
				h.Write([]byte(data))
				if fmt.Sprintf("%x\n", h.Sum(nil)) != secret["sha256sum"] {
					return errors.New("Invalid certs.  Secrets are updated afterwards?")
				}

				// TODO: Verify cacert, cert and key are okay.
				// TODO: Merge CA.
				if err := internalca.ApplyInternalCerts(cacert, cert, key); err != nil {
					return err
				}

				// TODO: Verify all nodes are in the same state.

				// Nothing changed. See you next round.
				crd.Status[name] = "mergedca"
				if err := watcher.SetState(context.TODO(), &crd); err != nil {
					return err
				}
				return nil
			})
			if err != nil {
				log.WithError(err).Error("Failed to handle events. Ignore.")
				if err := RetryOnConflict(DefaultBackOff, func() error {
					crd, err := watcher.GetCRD(context.TODO(), nil)
					if err != nil {
						return err
					}
					crd.Status[name] = "failed"
					if err := watcher.SetState(context.TODO(), &crd); err != nil {
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

	modifyca := func() {
		watcher.SetSecret(context.TODO(), "newca", map[string]string{
			"cacert":    "newcacert",
			"cert":      "newcert",
			"key":       "newkey",
			"sha256sum": "d3a5258e95b39b9a375dcc25569914db019d11053f7430716e25521ba5c2607b",
		})
		//internalca.ApplyInternalCerts("oldca")
		watcher.SetState(context.TODO(), &ClusterDataCRD{
			Spec: map[string]string{
				"oldca": "oldca",
				"newca": "newca",
			},
		})
	}

	go consul_node_reconcile("A")
	go consul_node_reconcile("B")
	go consul_node_reconcile("C")
	modifyca()
	time.Sleep(time.Second * 10)

	watcher.Exit()
	t.Log("completed")

	return
}
