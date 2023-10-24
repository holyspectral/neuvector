package syncutils

import (
	"context"
	"fmt"
	"math"
	"time"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

const (
	InternalCertStatusFailed      = "failed"
	InternalCertStatusUndefined   = ""
	InternalCertStatusMergedCA    = "merged-ca"
	InternalCertStatusMergedCAKey = "merged-ca-new-key"
	InternalCertStatusNewCAKey    = "new-ca-new-key"
	InternalCertStatusSuccess     = "success"
)

var InternalCertMap = map[string]int{
	InternalCertStatusFailed:      -1, // TODO: need extra handling
	InternalCertStatusUndefined:   0,
	InternalCertStatusMergedCA:    1,
	InternalCertStatusMergedCAKey: 2,
	InternalCertStatusNewCAKey:    3,
	InternalCertStatusSuccess:     4,
}

// TODO: Need more testing.
func ShouldWaitForOtherNodes(nodeNum int, currentStatus string, nodeStatus map[string]ClusterConsulNodeStatus) (bool, error) {
	if len(nodeStatus) < nodeNum && currentStatus != InternalCertStatusUndefined {
		// Some nodes didn't report yet.  Do not move to next stage that soon.
		return true, nil
	}
	if currentStatus == InternalCertStatusSuccess {
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
		diff := nodeStatusID - currentStatusID
		if nodeStatusID != 0 && currentStatusID != 0 && math.Abs(float64(diff)) > 1 {
			// Something is wrong. One node moves too fast.
			return false, fmt.Errorf("invalid status: current: %v, node: %v, diff: %v", currentStatusID, nodeStatusID, diff)
		}
	}
	return faster, nil
}

func UpgradeInternalCerts(name string, ss SynchronizedStorageAccess, certProvider InternalCertProvider) {
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
