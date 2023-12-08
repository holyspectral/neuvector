package cluster

import (
	"sync"

	"github.com/pkg/errors"
)

type ReloadableGRPCServer struct {
	grpcServer *GRPCServer
	reloadFunc func() (*GRPCServer, error)
	mutex      sync.Mutex
}

func NewReloadableGRPCServer(reloadFunc func() (*GRPCServer, error)) *ReloadableGRPCServer {
	return &ReloadableGRPCServer{
		reloadFunc: reloadFunc,
	}
}

func (r *ReloadableGRPCServer) Start() error {
	return r.Reload()
}

func (r *ReloadableGRPCServer) Reload() error {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	if r.grpcServer != nil {
		r.grpcServer.GracefulStop()
	}
	grpcServer, err := r.reloadFunc()
	if err != nil {
		return errors.Wrap(err, "failed to create grpc server")
	}
	r.grpcServer = grpcServer
	return nil
}

func (r *ReloadableGRPCServer) Get() *GRPCServer {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	return r.grpcServer
}

func (r *ReloadableGRPCServer) Stop() {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	r.grpcServer.Stop()
}
