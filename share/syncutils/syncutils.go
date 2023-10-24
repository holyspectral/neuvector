package syncutils

import (
	"context"
	"time"

	"github.com/pkg/errors"

	log "github.com/sirupsen/logrus"
	"k8s.io/apimachinery/pkg/util/wait"
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

var DefaultBackOff = wait.Backoff{
	Steps:    10,
	Duration: 10 * time.Millisecond,
	Factor:   1.0,
	Jitter:   0.1,
}

func RetryOnConflict(backoff wait.Backoff, fn func() error) error {
	return wait.ExponentialBackoff(backoff, func() (bool, error) {
		err := fn()
		if err != nil {
			log.WithError(err).Debug("failed to handle event")
			if err == ConflictError {
				return false, nil
			} else {
				return false, err
			}
		}
		return true, nil
	})
}

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

type InternalCertProvider interface {
	// Return cacert, cert, key.
	GetInternalCerts() (string, string, string, error)
	ApplyInternalCerts(cacert string, cert string, key string) error
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
