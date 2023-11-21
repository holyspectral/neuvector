package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"path"
	"sync"
	"time"

	"github.com/pkg/errors"

	corev1 "github.com/neuvector/k8s/apis/core/v1"
	"github.com/neuvector/neuvector/controller/common"
	"github.com/neuvector/neuvector/controller/resource"
	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/cluster"
	"github.com/neuvector/neuvector/share/global"
	log "github.com/sirupsen/logrus"
)

const DefaultMigrationGRPCStartRetry = 10

var reloadLock sync.Mutex

type MigrationService struct {
	Reloads []func([]byte, []byte, []byte) error
}

// TODO: Change me
const certName = "neuvector-internal-certs-active"

// This function rejects empty data.
func decodeBase64(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, errors.New("empty data")
	}

	if cert, err := base64.StdEncoding.DecodeString(string(data)); err != nil {
		return nil, err
	} else {
		return cert, nil
	}
}

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

// Reload cert from specified secret
func ReloadCert() ([]byte, []byte, []byte, error) {
	reloadLock.Lock()
	defer reloadLock.Unlock()

	// TODO: Check orchestration
	var obj interface{}
	var err error
	var cacert []byte
	var cert []byte
	var key []byte
	var secret *corev1.Secret
	var ok bool
	// 1. Load internal certs
	if obj, err = global.ORCH.GetResource(resource.RscTypeSecret, resource.NvAdmSvcNamespace, certName); err != nil {
		log.WithError(err).Error("no internal certificates are available.")
		// Failed to find internal certs.
		if err == common.ErrObjectNotFound {
			return nil, nil, nil, err
		}
		return nil, nil, nil, errors.Wrap(err, "no internal certificates are available.")
	}

	if secret, ok = obj.(*corev1.Secret); !ok || secret == nil {
		return nil, nil, nil, errors.New("invalid secret")
	}

	data := secret.GetData()
	if data == nil {
		return nil, nil, nil, errors.New("data in secret are not found")
	}

	cacert = data["ca.cert"]
	cert = data["cert.pem"]
	key = data["key.pem"]

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
func startMigrationGRPCServer(port uint16, reloadFuncs []func([]byte, []byte, []byte) error) (*cluster.GRPCServer, error) {
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
			"/etc/neuvector/certs/internal/migration/key.pem")
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
