package main

import (
	"context"
	"fmt"
	"time"

	"github.com/pkg/errors"

	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/cluster"
	log "github.com/sirupsen/logrus"
)

const DefaultMigrationGRPCStartRetry = 10

type MigrationService struct {
}

func (ms *MigrationService) Reload(ctx context.Context, in *share.ReloadRequest) (*share.ReloadResponse, error) {
	return nil, nil
}

// This function would block if it fails to bind port.  Use a go routine to call it instead.
func startMigrationGRPCServer(port uint16) (*cluster.GRPCServer, error) {
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

	share.RegisterMigrationServiceServer(grpc.GetServer(), new(MigrationService))
	go grpc.Start()

	log.Info("Migration GRPC server started")

	return grpc, nil
}
