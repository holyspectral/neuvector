package cluster

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"

	"google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/credentials"

	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/utils"
)

const legacyInternalCert = `-----BEGIN CERTIFICATE-----
MIIDDjCCAfagAwIBAgIBCjANBgkqhkiG9w0BAQUFADBPMQswCQYDVQQGEwJVUzET
MBEGA1UECAwKQ2FsaWZvcm5pYTEXMBUGA1UECgwOTmV1VmVjdG9yIEluYy4xEjAQ
BgNVBAMMCU5ldVZlY3RvcjAeFw0xNjA1MTkwNTIzNTFaFw0yNjA1MTcwNTIzNTFa
ME8xEjAQBgNVBAMMCU5ldVZlY3RvcjETMBEGA1UECAwKQ2FsaWZvcm5pYTELMAkG
A1UEBhMCVVMxFzAVBgNVBAoMDk5ldVZlY3RvciBJbmMuMIGfMA0GCSqGSIb3DQEB
AQUAA4GNADCBiQKBgQDCBCP7TMP85N8Rtx9jEe185Efzx0h1TEJSB7lLmYQfnhH1
IAEuOKGkTEguRRQ1s6ye8x0TIAo1z82kd22jqFJfp0qWpiIgH9hHuhqK/qVEh91+
CoxDVxWL7xMRZ8QO0ojDsL4aqApN3iAiBKwrZH4Vu/9yHV4Te54cPZcVRiogWQID
AQABo3kwdzAJBgNVHRMEAjAAMB0GA1UdDgQWBBSJEAj2YIUG6oJB7lEq/ERnO9nW
PTAfBgNVHSMEGDAWgBSulkDMGbtLm/vz34w1ofRKW2A8FjALBgNVHQ8EBAMCBaAw
HQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMA0GCSqGSIb3DQEBBQUAA4IB
AQCAv9XTCoubduFh/7zu8X/el0XVWfwGtt59ReGnjAZYPivz6E9W1PeaqgImbwV+
z+ams2R1AJMx4MbgW3Adg3z7YTRD7AvPJGZmJhoL8ye9F5zssbuJAw+FzVB+5Y3f
2eBWh6drESP4JjIkjoHJH5RcVXs1CcV72Sm+TigCTwCHVXKrsEV82v+SEIQnynYU
xrLiZCUPEBvhkRCq729hmj6gKItBRoNXFOpluNODHcKMLMO/HyszzaZJ26/+IPwp
oCBdIm4QPUEvQEp0hbJTd6jyVvFXyVurdnAFxruPKzxuHous3cnTN1hQdbloQmCd
54MQkihsy8aHFAnbBN8WLGUf
-----END CERTIFICATE-----
`

const GRPCMaxMsgSize = 1024 * 1024 * 32

var subjectCN string

func middlefunc(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (resp interface{}, err error) {
	// get client tls info
	/*
		if p, ok := peer.FromContext(ctx); ok {
			if mtls, ok := p.AuthInfo.(credentials.TLSInfo); ok {
				for _, item := range mtls.State.PeerCertificates {
					log.WithFields(log.Fields{"subject": item.Subject}).Info("grpc cert")
				}
			}
		}
	*/
	return handler(ctx, req)
}

// --

type GRPCServer struct {
	stopped bool
	listen  net.Listener
	server  *grpc.Server
}

func NewGRPCServerTCP(endpoint string) (*GRPCServer, error) {
	// CA cert
	caCert, err := ioutil.ReadFile(fmt.Sprintf("%s%s", internalCertDir, internalCACert))
	if err != nil {
		return nil, err
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	// public/private keys
	cert, err := tls.LoadX509KeyPair(
		fmt.Sprintf("%s%s", internalCertDir, internalCert),
		fmt.Sprintf("%s%s", internalCertDir, internalCertKey))
	if err != nil {
		return nil, err
	}

	config := &tls.Config{
		ClientCAs:                caCertPool,
		Certificates:             []tls.Certificate{cert},
		MinVersion:               tls.VersionTLS11,
		PreferServerCipherSuites: true,
		CipherSuites:             utils.GetSupportedTLSCipherSuites(),
		ClientAuth:               tls.RequireAndVerifyClientCert,
	}
	creds := credentials.NewTLS(config)

	opts := []grpc.ServerOption{
		grpc.Creds(creds),
		grpc.UnaryInterceptor(middlefunc),
		grpc.RPCCompressor(grpc.NewGZIPCompressor()),
		grpc.RPCDecompressor(grpc.NewGZIPDecompressor()),
		grpc.MaxMsgSize(GRPCMaxMsgSize),
	}

	listen, err := net.Listen("tcp", endpoint)
	if err != nil {
		return nil, err
	}

	s := GRPCServer{
		stopped: true,
		listen:  listen,
		server:  grpc.NewServer(opts...),
	}
	return &s, nil
}

func NewGRPCServerUnix(socket string) (*GRPCServer, error) {
	opts := []grpc.ServerOption{
		grpc.RPCCompressor(grpc.NewGZIPCompressor()),
		grpc.RPCDecompressor(grpc.NewGZIPDecompressor()),
		grpc.MaxMsgSize(GRPCMaxMsgSize),
	}

	listen, err := net.Listen("unix", socket)
	if err != nil {
		return nil, err
	}

	s := GRPCServer{
		stopped: true,
		listen:  listen,
		server:  grpc.NewServer(opts...),
	}
	return &s, nil
}

func (s *GRPCServer) GetServer() *grpc.Server {
	return s.server
}

func (s *GRPCServer) Start() {
	s.stopped = false
	for {
		if err := s.server.Serve(s.listen); err != nil {
			if s.stopped {
				break
			} else {
				log.WithFields(log.Fields{"error": err}).Error("Fail to start grpc server")
				time.Sleep(time.Second * 5)
			}
		}
	}
}

func (s *GRPCServer) Stop() {
	s.stopped = true
	s.server.Stop()
}

func (s *GRPCServer) GracefulStop() {
	s.server.GracefulStop()
}

type GRPCCallback interface {
	Shutdown()
}

type GRPCClient struct {
	conn   *grpc.ClientConn
	server string
	key    string
	cb     GRPCCallback
}

func (c *GRPCClient) GetClient() *grpc.ClientConn {
	return c.conn
}

func (c *GRPCClient) Close() {
	if c.conn != nil {
		c.conn.Close()
	}
}

func (c *GRPCClient) monitorGRPCConnectivity(ctx context.Context) {
	// Wait until connection is shutdown
	s := c.conn.GetState()
	for {
		log.WithFields(log.Fields{"state": s}).Debug("grpc connection state")

		// Even when server shutdown, client grpc channel is in TransientFailure state.
		if s == connectivity.Shutdown {
			c.shutdown()
			return
		} else if s == connectivity.TransientFailure {
			// In case the connection is in transient state, wait a second and check state again.
			time.Sleep(time.Second)
			s = c.conn.GetState()
			if s == connectivity.Shutdown || s == connectivity.TransientFailure {
				c.shutdown()
				return
			}
		}
		changed := c.conn.WaitForStateChange(ctx, s)
		if !changed {
			log.Debug("grpc connection state monitor cancelled")
			return
		}

		s = c.conn.GetState()
	}
}

func getTLSConfig(ctx context.Context, config *tls.Config, endpoint string) error {
	// TODO: remove hardcode
	c, cancel := context.WithTimeout(ctx, time.Second*3)
	defer cancel()
	creds := credentials.NewTLS(config)

	// This compress check is to be compatible with pre-3.2 grpc server that doesn't install decompressor.
	// Here we specify WithBlock() because we want to know if the connection is established before API calls, so we can fallback as early as possible.
	var opts []grpc.DialOption
	opts = []grpc.DialOption{
		grpc.WithTransportCredentials(creds),
		grpc.WithDecompressor(grpc.NewGZIPDecompressor()),
		grpc.WithCompressor(grpc.NewGZIPCompressor()),
		grpc.WithDefaultCallOptions(grpc.FailFast(true)),
		grpc.WithBlock(),
	}

	conn, err := grpc.DialContext(c, endpoint, opts...)
	if err != nil {
		return nil
	}
	conn.Close()
	return nil
}

func dialWithTLSConfig(ctx context.Context, config *tls.Config, endpoint string, compress bool) (*grpc.ClientConn, error) {
	creds := credentials.NewTLS(config)

	// This compress check is to be compatible with pre-3.2 grpc server that doesn't install decompressor.
	// Here we specify WithBlock() because we want to know if the connection is established before API calls, so we can fallback as early as possible.
	var opts []grpc.DialOption
	if compress {
		opts = []grpc.DialOption{
			grpc.WithTransportCredentials(creds),
			grpc.WithDecompressor(grpc.NewGZIPDecompressor()),
			grpc.WithCompressor(grpc.NewGZIPCompressor()),
			grpc.WithDefaultCallOptions(grpc.FailFast(true)),
		}
	} else {
		opts = []grpc.DialOption{
			grpc.WithTransportCredentials(creds),
			grpc.WithDecompressor(grpc.NewGZIPDecompressor()),
			grpc.WithDefaultCallOptions(grpc.FailFast(true)),
		}
	}

	conn, err := grpc.DialContext(ctx, endpoint, opts...)
	if err != nil {
		return nil, err
	}
	return conn, nil
}

func newGRPCClientTCP(ctx context.Context, key, endpoint string, cb GRPCCallback, compress bool) (*GRPCClient, error) {
	var conn *grpc.ClientConn
	// CA cert
	caCert, err := ioutil.ReadFile(fmt.Sprintf("%s%s", internalCertDir, internalCACert))
	if err != nil {
		return nil, err
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	// public/private keys
	cert, err := tls.LoadX509KeyPair(
		fmt.Sprintf("%s%s", internalCertDir, internalCert),
		fmt.Sprintf("%s%s", internalCertDir, internalCertKey))
	if err != nil {
		return nil, err
	}

	// The assumption is the server and client will use the same set of keys,
	// so we can use CN in the local public key to get the server name.
	if subjectCN == "" {
		for _, certData := range cert.Certificate {
			if cert, err := x509.ParseCertificate(certData); err == nil {
				subjectCN = cert.Subject.CommonName
				break
			}
		}

		if subjectCN == "" {
			subjectCN = internalCertCN
		}

		log.WithFields(log.Fields{"cn": subjectCN}).Info("Expected server name")
	}

	tlsconfig := &tls.Config{
		RootCAs:      caCertPool,
		Certificates: []tls.Certificate{cert},
		ServerName:   subjectCN,
	}

	if err = checkTLSConfig(ctx, tlsconfig, endpoint); err != nil && strings.Contains(err.Error(), "x509: certificate relies on legacy Common Name field, use SANs instead") {
		log.WithError(err).Info("Failed to establish grpc connection...attempt to migrate")

		fallbackcfg := &tls.Config{
			RootCAs:            caCertPool,
			Certificates:       []tls.Certificate{cert},
			ServerName:         subjectCN,
			InsecureSkipVerify: true,
			VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
				// Certificate pinning.
				p, _ := pem.Decode([]byte(legacyInternalCert))
				if p == nil {
					return errors.New("failed to decode legacy certificate")
				}
				if len(rawCerts) != 1 {
					return errors.New("unrecognized certificate.  Give up.")
				}
				log.Warn("A: ", p.Bytes)
				log.Warn("B: ", rawCerts[0])
				if !bytes.Equal(p.Bytes, rawCerts[0]) {
					return errors.New("unrecognized certificate.  Give up.")
				}
				return nil
			},
		}

		// TODO: Disable this behavior when necessary.
		if err = checkTLSConfig(ctx, fallbackcfg, endpoint); err == nil {
			tlsconfig = fallbackcfg
		}
	}

	// There should be a valid conn now.

	c := &GRPCClient{conn: conn, key: key, server: endpoint, cb: cb}

	// TODO: one go routine per connection, should consider combine them if this is too many.
	go c.monitorGRPCConnectivity(ctx)

	return c, nil
}

func newGRPCClientUnix(ctx context.Context, key, socket string, cb GRPCCallback, compress bool) (*GRPCClient, error) {
	var opts []grpc.DialOption
	if compress {
		opts = []grpc.DialOption{
			grpc.WithInsecure(),
			grpc.WithDecompressor(grpc.NewGZIPDecompressor()),
			grpc.WithCompressor(grpc.NewGZIPCompressor()),
			grpc.WithDefaultCallOptions(grpc.FailFast(true)),
			grpc.WithDialer(func(addr string, timeout time.Duration) (net.Conn, error) {
				return net.DialTimeout("unix", addr, timeout)
			}),
		}
	} else {
		opts = []grpc.DialOption{
			grpc.WithInsecure(),
			grpc.WithDecompressor(grpc.NewGZIPDecompressor()),
			grpc.WithDefaultCallOptions(grpc.FailFast(true)),
			grpc.WithDialer(func(addr string, timeout time.Duration) (net.Conn, error) {
				return net.DialTimeout("unix", addr, timeout)
			}),
		}
	}

	conn, err := grpc.DialContext(ctx, socket, opts...)
	if err != nil {
		return nil, err
	}

	c := &GRPCClient{conn: conn, key: key, server: socket, cb: cb}

	go c.monitorGRPCConnectivity(ctx)

	return c, nil
}

/*
 * In Pre-3.2 build, GRPC channel is not all gzip compressed. When this is changed
 * in 3.2, we have a compatibility issue. For example, when the new updater images
 * talk to the pre-3.2 controller.
 * So we create a new service to check if compress is enabled on the server. If
 * the API call is not supported or return false, the client will use uncompressed
 * channel to connect to the server.
 */

type IsCompressedFunc func(endpoint string) bool

func isUnixSocketEndpoint(endpoint string) bool {
	// Just a rough way to tell if an endpoint is a tcp endpoint or unix socket
	return !strings.Contains(endpoint, ":")
}

func createControllerCapServiceWrapper(conn *grpc.ClientConn) Service {
	return share.NewControllerCapServiceClient(conn)
}

func IsControllerGRPCCommpressed(endpoint string) bool {
	var err error
	var c *GRPCClient

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*60)
	defer cancel()

	if isUnixSocketEndpoint(endpoint) {
		c, err = newGRPCClientUnix(ctx, "", endpoint, nil, true)
	} else {
		c, err = newGRPCClientTCP(ctx, "", endpoint, nil, true)
	}
	if err != nil {
		log.WithFields(log.Fields{"err": err}).Error("Failed to get controller cap client")
		return false
	}

	s := share.NewControllerCapServiceClient(c.GetClient()).(share.ControllerCapServiceClient)

	cap, err := s.IsGRPCCompressed(ctx, &share.RPCVoid{})
	if err != nil || cap == nil || !cap.Value {
		return false
	} else {
		return true
	}
}

func createEnforcerCapServiceWrapper(conn *grpc.ClientConn) Service {
	return share.NewEnforcerCapServiceClient(conn)
}

func IsEnforcerGRPCCommpressed(endpoint string) bool {
	var err error
	var c *GRPCClient

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*60)
	defer cancel()

	if isUnixSocketEndpoint(endpoint) {
		c, err = newGRPCClientUnix(ctx, "", endpoint, nil, true)
	} else {
		c, err = newGRPCClientTCP(ctx, "", endpoint, nil, true)
	}
	if err != nil {
		log.WithFields(log.Fields{"err": err}).Error("Failed to get enforcer cap client")
		return false
	}

	s := share.NewEnforcerCapServiceClient(c.GetClient()).(share.EnforcerCapServiceClient)

	cap, err := s.IsGRPCCompressed(ctx, &share.RPCVoid{})
	if err != nil || cap == nil || !cap.Value {
		return false
	} else {
		return true
	}
}

/*
 * ----------------------------------------------------
 * ---------- Client management -----------------------
 * ----------------------------------------------------
 */
type Service interface{}
type CreateService func(conn *grpc.ClientConn) Service

type grpcClient struct {
	key        string
	endpoint   string
	autoRemove bool
	unix       bool
	client     *GRPCClient
	cancel     context.CancelFunc
	service    Service
	create     CreateService
}

var mtx sync.RWMutex
var clientMap map[string]*grpcClient = make(map[string]*grpcClient, 0)

func CreateGRPCClient(key, endpoint string, autoRemove bool, create CreateService) error {
	mtx.Lock()
	defer mtx.Unlock()
	if _, ok := clientMap[key]; !ok {
		c := &grpcClient{
			key:        key,
			endpoint:   endpoint,
			autoRemove: autoRemove,
			create:     create,
		}
		if isUnixSocketEndpoint(endpoint) {
			c.unix = true
		}
		clientMap[key] = c
	} else {
		return fmt.Errorf("Client exists")
	}
	return nil
}

func DeleteGRPCClient(key string) {
	mtx.Lock()
	defer mtx.Unlock()
	if s, ok := clientMap[key]; ok {
		if s.client != nil {
			s.cancel()
			s.client.Close()
		}
		delete(clientMap, key)
	}
}

func (c *GRPCClient) shutdown() {
	log.WithFields(log.Fields{"server": c.server}).Debug()

	mtx.Lock()
	if s, ok := clientMap[c.key]; ok {
		if s.client != nil {
			s.client.Close()
			s.client = nil
		}
		if s.autoRemove {
			delete(clientMap, c.key)
		}
	}
	mtx.Unlock()

	if c.cb != nil {
		c.cb.Shutdown()
	}
}

func newClient(s *grpcClient, cb GRPCCallback, compress bool) error {
	var err error
	var c *GRPCClient
	ctx, cancel := context.WithCancel(context.Background())
	if s.unix {
		c, err = newGRPCClientUnix(ctx, s.key, s.endpoint, cb, compress)
	} else {
		c, err = newGRPCClientTCP(ctx, s.key, s.endpoint, cb, compress)
	}
	if err != nil {
		log.WithFields(log.Fields{
			"error": err, "ep": s.endpoint,
		}).Error("Failed to dial to grpc server")
		return err
	}
	s.client = c
	s.cancel = cancel

	s.service = s.create(c.GetClient())
	return nil
}

// TODO: reduce lock time
func GetGRPCClient(key string, isCompressed IsCompressedFunc, cb GRPCCallback) (interface{}, error) {
	mtx.Lock()
	defer mtx.Unlock()
	if s, ok := clientMap[key]; ok {
		if s.client != nil {
			return s.service, nil
		}

		compress := true
		if isCompressed != nil {
			compress = isCompressed(s.endpoint)
		}

		log.WithFields(log.Fields{"ep": s.endpoint, "compress": compress}).Debug()

		err := newClient(s, cb, compress)
		if err == nil {
			return s.service, nil
		} else {
			return nil, err
		}
	}
	return nil, fmt.Errorf("Client not found")
}

func GetGRPCClientEndpoint(key string) string {
	mtx.Lock()
	defer mtx.Unlock()
	if s, ok := clientMap[key]; ok {
		return s.endpoint
	} else {
		return ""
	}
}
