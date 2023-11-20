package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"io/ioutil"
	"net"
	"strconv"

	"github.com/neuvector/neuvector/share"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	appv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/clientcmd"
	watchtools "k8s.io/client-go/tools/watch"
	"k8s.io/kubectl/pkg/polymorphichelpers"
)

// Will be built with Go 1.14 at the moment.
// TODO: Should we use existing library?  Options:
// 1. Use client-go + Go 1.16 => Need to patch build environment.  How?
// 2. Use client-go + Go 1.14 => Might work?  Need to figure out which version to use or patch.
// 3. Use global.ORCH.StartWatchResource + Go 1.14 => Could be complicated since we don't use it this way.

var (
	// TODO: change file name to align with cert-manger default.
	cacertPath = flag.String("cacert", "/etc/neuvector/certs/internal/migration/ca.cert", "CA cert path")
	certPath   = flag.String("cert", "/etc/neuvector/certs/internal/migration/cert.pem", "cert path")
	keyPath    = flag.String("key", "/etc/neuvector/certs/internal/migration/key.pem", "key path")
	subjectCN  = flag.String("subject", "NeuVector", "expected subject name from remote server")
	kubeconfig = flag.String("kubeconfig", "", "Paths to a kubeconfig. Only required if out-of-cluster.")
	namespace  = flag.String("namespace", "neuvector", "Kubernetes namespace that NeuVector is running in.")
	timeout    = flag.Duration("timeout", 0, "timeout for waiting deployment to complete")
	grpc_port  = flag.Int("grpc_port", 18500, "the listening port for migration gRPC server")
)

func main() {
	flag.Parse()
	var config *rest.Config
	var err error
	/*
		conn, err := NewGRPCClient(context.TODO(), "TODO", *cacertPath, *certPath, *keyPath, *subjectCN)
		if err != nil {
			log.WithError(err).Error("failed to create grpc client")
			return
		}

		mgClient := share.NewMigrationServiceClient(conn)
		mgClient.Reload(context.TODO(), &share.ReloadRequest{})
	*/

	if len(*kubeconfig) > 0 {
		config, err = clientcmd.BuildConfigFromFlags("", *kubeconfig)
		if err != nil {
			log.WithError(err).Panic("failed to build config from kubeconfig")
		}
	} else {
		config, err = rest.InClusterConfig()
		if err != nil {
			log.WithError(err).Fatal("failed to read in-cluster config")
		}
	}

	client, err := dynamic.NewForConfig(config)
	if err != nil {
		return
	}

	// 1. Wait until deployment completes
	ctx, cancel := watchtools.ContextWithOptionalTimeout(context.Background(), *timeout)
	defer cancel()
	err = WaitUntilRolledOut(ctx,
		schema.GroupVersionResource{Group: "apps", Version: "v1", Resource: "deployments"},
		"neuvector-controller-pod",
		client)

	// 2. Call grpc API of all controllers.
	items, err := client.Resource(
		schema.GroupVersionResource{
			Resource: "pods",
			Version:  "v1",
		},
	).Namespace(*namespace).List(context.TODO(), metav1.ListOptions{
		LabelSelector: fields.OneTermEqualSelector("app", "neuvector-controller-pod").String(),
	})

	if err != nil {
		log.WithError(err).Fatal("failed to list pods")
	}

	// TODO: Update certificate

	// Reload certs
	for _, item := range items.Items {
		var pod corev1.Pod
		err = runtime.DefaultUnstructuredConverter.
			FromUnstructured(item.UnstructuredContent(), &pod)
		// TODO: deal with terminating pods
		log.Println(pod.Status.PodIP)

		podAddress := net.JoinHostPort(pod.Status.PodIP, strconv.Itoa(*grpc_port))
		conn, err := NewGRPCClient(context.TODO(), podAddress, *cacertPath, *certPath, *keyPath, *subjectCN)
		if err != nil {
			log.WithError(err).Error("failed to create grpc client")
			return
		}

		mgClient := share.NewMigrationServiceClient(conn)
		resp, err := mgClient.Reload(context.TODO(), &share.ReloadRequest{})
		if err != nil {
			log.WithError(err).Error("failed to call reload API")
			return
		}
		log.WithFields(log.Fields{
			"resp": resp,
			"pod":  podAddress,
		}).Info("Certificate is reloaded")
	}
}

func WaitUntilRolledOut(ctx context.Context, gr schema.GroupVersionResource, name string, client dynamic.Interface) error {
	// Implement kubectl rollout status
	// See https://github.com/kubernetes/kubectl/blob/master/pkg/cmd/rollout/rollout_status.go
	// TODO: kubectl plugin?

	// 1. Get controller deployment.
	item, err := client.Resource(gr).Namespace(*namespace).Get(context.TODO(), name, metav1.GetOptions{})
	if err != nil {
		// something wrong to get the deployment.  Give up.
		return errors.Wrap(err, "failed to get neuvector-controller-pod deployment")
	}
	var deployment appv1.Deployment
	err = runtime.DefaultUnstructuredConverter.
		FromUnstructured(item.UnstructuredContent(), &deployment)

	fieldSelector := fields.OneTermEqualSelector("metadata.name", deployment.Name).String()
	lw := &cache.ListWatch{
		ListFunc: func(options metav1.ListOptions) (runtime.Object, error) {
			options.FieldSelector = fieldSelector
			return client.Resource(gr).Namespace(deployment.Namespace).List(context.TODO(), options)
		},
		WatchFunc: func(options metav1.ListOptions) (watch.Interface, error) {
			options.FieldSelector = fieldSelector
			return client.Resource(gr).Namespace(deployment.Namespace).Watch(context.TODO(), options)
		},
	}

	statusViewer, err := polymorphichelpers.StatusViewerFor(deployment.GroupVersionKind().GroupKind())
	if err != nil {
		return errors.Wrap(err, "failed to find status viewer")
	}

	// Wait until deployment finishes.  Note: this could last forever if some of pods can't be deployed.
	_, err = watchtools.UntilWithSync(ctx, lw, &unstructured.Unstructured{}, nil, func(e watch.Event) (bool, error) {
		select {
		case <-ctx.Done():
			return false, ctx.Err()
		default:
		}
		switch t := e.Type; t {
		case watch.Added, watch.Modified:
			// TODO: examine if revision=0 is appropriate.
			status, done, err := statusViewer.Status(e.Object.(runtime.Unstructured), 0)
			if err != nil {
				return false, err
			}
			log.Println(status)

			// Quit waiting if the rollout is done
			if done {
				return true, nil
			}

			return false, nil

		case watch.Deleted:
			// We need to abort to avoid cases of recreation and not to silently watch the wrong (new) object
			return true, fmt.Errorf("object has been deleted")

		default:
			return true, fmt.Errorf("internal error: unexpected event %#v", e)
		}
	})
	return err
}

func Reload(conn *grpc.ClientConn) {
	// TODO: call reload
	// TODO: Should we depend on share?
	client := share.NewMigrationServiceClient(conn)
	client.Reload(context.TODO(), &share.ReloadRequest{})
}

func NewGRPCClient(ctx context.Context, endpoint string, cacertPath string, certPath string, keyPath string, subject string) (*grpc.ClientConn, error) {
	caCert, err := ioutil.ReadFile(cacertPath)
	if err != nil {
		return nil, err
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	// public/private keys
	cert, err := tls.LoadX509KeyPair(
		certPath,
		keyPath)
	if err != nil {
		return nil, err
	}

	config := &tls.Config{
		RootCAs:      caCertPool,
		Certificates: []tls.Certificate{cert},
		ServerName:   subject,
	}
	creds := credentials.NewTLS(config)

	return grpc.DialContext(ctx, endpoint,
		grpc.WithTransportCredentials(creds),
		grpc.WithDecompressor(grpc.NewGZIPDecompressor()),
		grpc.WithCompressor(grpc.NewGZIPCompressor()),
		grpc.WithDefaultCallOptions(grpc.FailFast(true)),
	)
}
