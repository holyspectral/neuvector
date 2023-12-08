package main

import (
	"strings"

	"github.com/neuvector/neuvector/share/cluster"
	"github.com/neuvector/neuvector/share/migration"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

var (
	manager *CertReloadManager
)

type CertReloadManager struct {
	grpcServers         map[string]*cluster.ReloadableGRPCServer
	migrationGRPCServer *cluster.ReloadableGRPCServer
}

func GetCertReloadManager() *CertReloadManager {
	if manager != nil {
		return manager
	}

	manager = &CertReloadManager{
		grpcServers: map[string]*cluster.ReloadableGRPCServer{},
	}
	return manager
}

func (ic *CertReloadManager) Init() error {
	// Reload internal certificates.
	// However, internal certificates can be changed after this step, so further check is still needed
	if _, _, _, err := migration.ReloadCert(); err != nil {
		// Failed to reload cert.
		// TODO: better check
		if !strings.Contains(err.Error(), "not found") {
			// TODO: Make sure this is the only way to deal with the error
			log.WithError(err).Fatal("failed to reload kubernetes secret")
		}
	}

	// Define the services that you want to manage here.
	controllerGRPCServer := cluster.NewReloadableGRPCServer(func() (*cluster.GRPCServer, error) {
		server, _ := startGRPCServer(uint16(*grpcPort))
		return server, nil
	})

	ic.migrationGRPCServer = cluster.NewReloadableGRPCServer(func() (*cluster.GRPCServer, error) {
		server, err := migration.StartMigrationGRPCServer(uint16(*migrationGRPCPort), []func([]byte, []byte, []byte) error{
			// Reload consul
			func(cacert []byte, cert []byte, key []byte) error {
				if err := cluster.Reload(nil); err != nil {
					return errors.Wrap(err, "failed to reload consul")
				}
				return nil
			},
			// Reload grpc server
			func(cacert []byte, cert []byte, key []byte) error {
				for k, v := range ic.grpcServers {
					err := v.Reload()
					if err != nil {
						return errors.Wrapf(err, "failed to reload %s service", k)
					}
				}
				return nil
			},
			// Reload grpc client
			func(cacert []byte, cert []byte, key []byte) error {
				// TODO: Make sure all gRPC call retries.
				// TODO: Make sure server can completes normally without resource leak.
				// TODO: Add lock on grpcServer.
				if err := cluster.ReloadAllGRPCClients(); err != nil {
					return errors.Wrap(err, "failed to purge gRPC client cache")
				}
				return nil
			},
		})
		if err != nil {
			return nil, errors.Wrap(err, "failed to start migration grpc server")
		}
		return server, nil
	})

	ic.grpcServers["controller"] = controllerGRPCServer
	return nil
}

// This function gets internal certificates from k8s secret and register handlers for migration job to call.
func (ic *CertReloadManager) Start() error {
	ic.migrationGRPCServer.Start()
	return nil
}

func (ic *CertReloadManager) GetGRPCServer(key string) *cluster.ReloadableGRPCServer {
	server, ok := ic.grpcServers[key]
	if !ok {
		return nil
	}
	return server
}

func (ic *CertReloadManager) Shutdown() error {
	ic.migrationGRPCServer.Stop()
	ic.grpcServers["controller"].Stop()
	return nil
}
