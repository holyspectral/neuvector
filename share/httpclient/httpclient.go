package httpclient

import (
	"crypto/tls"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
)

type TLSClientSettings struct {
	TLSconfig *tls.Config
}

// To protect sharedTLSConfig, sharedTransport and sharedNoProxyTransport.
var lock sync.RWMutex

var sharedTLSConfig = &tls.Config{}
var sharedTransport *http.Transport
var sharedNoProxyTransport *http.Transport

// Create a http.Transport with the default setting.
func newTransport() *http.Transport {
	// http.DefaultTransport in golang 1.22.
	return &http.Transport{
		MaxIdleConnsPerHost: 10,
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
}

// Change TLS config based on input and update related connection pools (http.Transport).
//
// Note: When this function is called, a new set of connection pools will be created
// to prevent issue in the existing clients.
func SetDefaultTLSClientConfig(config *TLSClientSettings, httpProxy string, httpsProxy string, noProxy string) {
	lock.Lock()
	defer lock.Unlock()

	// If user's config is with proxy disabled, they will need their own transport.
	getProxy := func(req *http.Request) (*url.URL, error) {
		// Check if proxy should be skipped for the registry URL
		noProxyHosts := strings.Split(noProxy, ",")
		for _, noProxyHost := range noProxyHosts {
			if noProxyHost != "" {
				noProxyHost = strings.Replace(noProxyHost, "*", ".*", -1)
				if regx, err := regexp.Compile(noProxyHost); err == nil && regx.MatchString(req.URL.Hostname()) {
					log.WithFields(log.Fields{"hostname": req.URL.Hostname(), "noProxyHost": noProxyHost}).Debug("No need proxy")
					return nil, nil
				}
			}
		}

		if req.URL.Scheme == "https" {
			return url.Parse(httpsProxy)
		}
		return url.Parse(httpProxy)
	}

	// Initialize http.Transport
	sharedTransport = newTransport()
	sharedTransport.TLSClientConfig = config.TLSconfig
	sharedTransport.Proxy = getProxy

	sharedNoProxyTransport = newTransport()
	sharedNoProxyTransport.TLSClientConfig = config.TLSconfig
	sharedNoProxyTransport.Proxy = nil

	sharedTLSConfig = config.TLSconfig
}

// Get the shared http.Transport/connection pool.
func GetSharedTransport() *http.Transport {
	lock.RLock()
	defer lock.RUnlock()

	return sharedTransport
}

// Get the shared http.Transport/connection pool without a proxy assigned.
func GetNoProxySharedTransport() *http.Transport {
	lock.RLock()
	defer lock.RUnlock()

	return sharedNoProxyTransport
}

// Get the current TLS config
//
// This function doesn't support proxy, so it's recommended
// to use GetSharedTransport() or CreateHTTPClient()instead in most use cases.
func GetTLSConfig() *tls.Config {
	lock.RLock()
	defer lock.RUnlock()

	return sharedTLSConfig
}

// Create a HTTP client with shared transport, which contains proxy and TLS settings.
func CreateHTTPClient() *http.Client {
	lock.RLock()
	defer lock.RUnlock()

	return &http.Client{
		Transport: sharedTransport,
	}
}

// Create a HTTP client with shared transport, which contains shared TLS settings but no proxy assigned.
func CreateNoProxyHTTPClient() *http.Client {
	lock.RLock()
	defer lock.RUnlock()

	return &http.Client{
		Transport: sharedNoProxyTransport,
	}
}
