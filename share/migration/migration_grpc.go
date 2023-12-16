package migration

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"path"
	"sync"
	"time"

	"github.com/pkg/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/rest"

	corev1 "github.com/neuvector/k8s/apis/core/v1"
	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/cluster"
	log "github.com/sirupsen/logrus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	DefaultMigrationGRPCStartRetry = 10

	ACTIVE_CACERT_FILENAME = "active-ca.crt"
	ACTIVE_CERT_FILENAME   = "active-tls.crt"
	ACTIVE_KEY_FILENAME    = "active-tls.key"
)

var reloadLock sync.Mutex

type MigrationService struct {
	Reloads []func([]byte, []byte, []byte) error
}

// TODO: Change me
const certName = "neuvector-internal-certs"

func verifyCert(cacert []byte, cert []byte, key []byte) error {

	roots := x509.NewCertPool()
	ok := roots.AppendCertsFromPEM(cacert)
	if !ok {
		return errors.New("failed to append cert")
	}

	block, _ := pem.Decode(cert)
	if block == nil {
		return errors.New("failed to decode cert")
	}
	crt, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return errors.Wrap(err, "failed to parse certificate")
	}

	opts := x509.VerifyOptions{
		Roots:         roots,
		DNSName:       cluster.InternalCertCN,
		Intermediates: x509.NewCertPool(),
	}

	if _, err := crt.Verify(opts); err != nil {
		return errors.Wrap(err, "failed to verify certificate")
	}

	if _, err := tls.X509KeyPair(cert, key); err != nil {
		return errors.Wrap(err, "invalid key cert pair")
	}
	return nil
}

func GetK8sSecret(ctx context.Context, client dynamic.Interface, name string) (*corev1.Secret, error) {
	// TODO: Change namespace
	item, err := client.Resource(
		schema.GroupVersionResource{
			Resource: "secrets",
			Version:  "v1",
		},
	).Namespace("neuvector").Get(ctx, name, metav1.GetOptions{})

	if err != nil {
		return nil, errors.Wrap(err, "failed to get secret")
	}

	var targetSecret corev1.Secret
	err = runtime.DefaultUnstructuredConverter.
		FromUnstructured(item.UnstructuredContent(), &targetSecret)
	if err != nil {
		return nil, errors.Wrap(err, "failed to parse target secret")
	}
	return &targetSecret, nil
}

// Reload cert from specified secret.
// TODO: Tolerate temporary errors from API server.
func ReloadCert() ([]byte, []byte, []byte, error) {
	reloadLock.Lock()
	defer reloadLock.Unlock()

	// TODO: Check orchestration
	var err error
	var cacert []byte
	var cert []byte
	var key []byte
	var secret *corev1.Secret

	config, err := rest.InClusterConfig()
	if err != nil {
		return nil, nil, nil, errors.Wrap(err, "failed to get config")
	}
	client, err := dynamic.NewForConfig(config)
	if err != nil {
		return nil, nil, nil, errors.Wrap(err, "failed to get dynamic client")
	}
	secret, err = GetK8sSecret(context.TODO(), client, certName)
	if err != nil {
		return nil, nil, nil, errors.Wrap(err, "failed to get secret")
	}

	// 1. Load internal certs

	data := secret.GetData()
	if data == nil {
		return nil, nil, nil, errors.New("data in secret are not found")
	}

	cacert = data[ACTIVE_CACERT_FILENAME]
	cert = data[ACTIVE_CERT_FILENAME]
	key = data[ACTIVE_KEY_FILENAME]

	if len(cacert) == 0 || len(cert) == 0 || len(key) == 0 {
		// No active certs
		return nil, nil, nil, nil
	}
	if err := verifyCert(cacert, cert, key); err != nil {
		return nil, nil, nil, errors.Wrap(err, "invalid key/cert")
	}

	// TODO: Sanity check to see if cacert can accept both old and new cert.

	if err := ioutil.WriteFile(path.Join(cluster.InternalCertDir, cluster.InternalCACert), []byte(cacert), 0600); err != nil {
		return nil, nil, nil, errors.Wrap(err, "failed to write cacert")
	}
	if err := ioutil.WriteFile(path.Join(cluster.InternalCertDir, cluster.InternalCert), []byte(cert), 0600); err != nil {
		return nil, nil, nil, errors.Wrap(err, "failed to write cert")
	}
	if err := ioutil.WriteFile(path.Join(cluster.InternalCertDir, cluster.InternalCertKey), []byte(key), 0600); err != nil {
		return nil, nil, nil, errors.Wrap(err, "failed to write key")
	}
	return cacert, cert, key, nil
}

// TODO: Reload should be called when restart
func (ms *MigrationService) Reload(ctx context.Context, in *share.ReloadRequest) (*share.ReloadResponse, error) {
	var cacert []byte
	var cert []byte
	var key []byte
	// Make sure only one caller at all time.
	cacert, cert, key, err := ReloadCert()
	if err != nil {
		log.WithError(err).Error("failed to reload certs")
		return &share.ReloadResponse{
			Success: false,
			Error:   errors.Wrap(err, "failed to reload certs").Error(),
		}, nil
	}

	for _, f := range ms.Reloads {
		if err := f(cacert, cert, key); err != nil {
			log.WithError(err).Error("failed to reload certs")
			return &share.ReloadResponse{
				Success: false,
				Error:   "failed to reload certs",
			}, nil
		}
	}

	// TODO: Reload cert for gRPC.
	// TODO: Health check
	return &share.ReloadResponse{
		Success: true,
		Error:   "",
	}, nil
}

// This function would block if it fails to bind port.  Use a go routine to call it instead.
func StartMigrationGRPCServer(port uint16, reloadFuncs []func([]byte, []byte, []byte) error) (*cluster.GRPCServer, error) {
	var grpc *cluster.GRPCServer
	var err error

	if port == 0 {
		return nil, errors.New("No port is specified")
	}
	endpoint := fmt.Sprintf(":%d", port)

	log.WithFields(log.Fields{"endpoint": endpoint}).Info("starting migration gRPC server")
	for i := 0; i < DefaultMigrationGRPCStartRetry; i++ {
		grpc, err = cluster.NewGRPCServerTCPWithCerts(endpoint,
			"/etc/neuvector/certs/internal/migration/ca.cert",
			"/etc/neuvector/certs/internal/migration/cert.pem",
			"/etc/neuvector/certs/internal/migration/key.pem",
			tls.VersionTLS12,
		)
		if err != nil {
			log.WithFields(log.Fields{"error": err}).Error("Fail to create GRPC server")
			// Sometimes port is not ready for reuse.  Retry.
			time.Sleep(time.Second * 5)
		} else {
			break
		}
	}
	if err != nil {
		// gRPC server couldn't start in time.
		return nil, err
	}

	share.RegisterMigrationServiceServer(grpc.GetServer(), &MigrationService{
		Reloads: reloadFuncs,
	})
	go grpc.Start()

	log.Info("Migration GRPC server started")

	return grpc, nil
}
