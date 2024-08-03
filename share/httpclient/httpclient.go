package httpclient

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/global"
	log "github.com/sirupsen/logrus"
)

type TLSClientSettings struct {
	TLSconfig *tls.Config
}

// To protect sharedTLSConfig, sharedTransport and sharedNoProxyTransport.
var lock sync.RWMutex

var httpProxyConfig string
var httpsProxyConfig string

var sharedTLSConfig = &tls.Config{}
var transportCache map[string]*http.Transport

//var sharedTransport *http.Transport
//var sharedNoProxyTransport *http.Transport

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

// Convert share.CLUSProxy to a proxy url with username and password.
func ParseProxy(proxy *share.CLUSProxy) string {
	if proxy != nil && proxy.Enable {
		url, err := url.Parse(proxy.URL)
		if err != nil {
			return ""
		}
		if proxy.Username != "" {
			return fmt.Sprintf("%s://%s:%s@%s:%s/",
				url.Scheme, proxy.Username, proxy.Password, url.Hostname(), url.Port())
		} else {
			return fmt.Sprintf("%s://%s:%s/",
				url.Scheme, url.Hostname(), url.Port())
		}
	}
	return ""
}

func GetProxy(targetURL string) (string, error) {
	lock.RLock()
	defer lock.RUnlock()

	u, err := url.Parse(targetURL)
	if err != nil {
		log.WithError(err).Warn("failed to parse target url")
		return "", fmt.Errorf("failed to parse target url: %w", err)
	}

	// Check if proxy should be skipped for the URL
	// TODO: Should we honor this in all connections?
	var httpProxy, httpsProxy, noProxy string
	if global.RT != nil { // in case of unitest
		httpProxy, httpsProxy, noProxy = global.RT.GetProxy()
		noProxyHosts := strings.Split(noProxy, ",")
		for _, noProxyHost := range noProxyHosts {
			if noProxyHost != "" {
				noProxyHost = strings.Replace(noProxyHost, "*", ".*", -1)
				if regx, err := regexp.Compile(noProxyHost); err == nil && regx.MatchString(u.Hostname()) {
					log.WithFields(log.Fields{"hostname": u.Hostname(), "noProxyHost": noProxyHost}).Debug("No need proxy")
					return "", nil
				}
			}
		}
	}

	// Return configured proxy if enabled, otherwise return container runtime's settings
	proxy := ""
	if u.Scheme == "https" {
		if httpsProxyConfig != "" {
			proxy = httpProxyConfig
		} else {
			proxy = httpsProxy
		}
	} else {
		if httpProxyConfig != "" {
			proxy = httpProxyConfig
		} else {
			proxy = httpProxy
		}
	}
	return proxy, nil
}

// Change TLS config based on input and update related connection pools (http.Transport).
//
// Note: When this function is called, a new set of connection pools will be created
// to prevent issue in the existing clients.
func SetDefaultTLSClientConfig(config *TLSClientSettings, httpProxy string, httpsProxy string, noProxy string) error {
	lock.Lock()
	defer lock.Unlock()

	/*
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
	*/

	// Examine inputs
	httpsProxyURL, err := url.Parse(httpsProxy)
	if err != nil {
		return fmt.Errorf("failed to parse proxy: %w", err)
	}

	httpProxyURL, err := url.Parse(httpProxy)
	if err != nil {
		return fmt.Errorf("failed to parse proxy: %w", err)
	}

	// Cleanup the existing cache and create a new one.
	// This will make the cache and its content (http.Transport) be GCed if they're not referenced anymore.
	transportCache = make(map[string]*http.Transport)

	// Initialize https proxy's transport

	t := newTransport()
	t.TLSClientConfig = config.TLSconfig
	t.Proxy = http.ProxyURL(httpsProxyURL)
	transportCache[httpsProxy] = t

	// Initialize http proxy's transport
	t = newTransport()
	t.TLSClientConfig = config.TLSconfig
	t.Proxy = http.ProxyURL(httpProxyURL)
	transportCache[httpProxy] = t

	// Initialize no proxy's transport
	t = newTransport()
	t.TLSClientConfig = config.TLSconfig
	t.Proxy = nil
	transportCache[""] = t

	// Cache related settings
	httpProxyConfig = httpProxy
	httpsProxyConfig = httpsProxy

	sharedTLSConfig = config.TLSconfig

	return nil
}

// Get the shared http.Transport if possible.
// If the proxy specified is not the one in global settings, create a new transport for it.
func GetTransport(proxy string) (*http.Transport, error) {
	lock.RLock()
	defer lock.RUnlock()
	t, ok := transportCache[proxy]
	if !ok {
		t = newTransport()
		t.TLSClientConfig = sharedTLSConfig

		proxyURL, err := url.Parse(proxy)
		if err != nil {
			return nil, fmt.Errorf("failed to parse proxy: %w", err)
		}
		t.Proxy = http.ProxyURL(proxyURL)
	}

	return t, nil
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
func CreateHTTPClient(proxy string) (*http.Client, error) {
	lock.RLock()
	defer lock.RUnlock()

	transport, err := GetTransport(proxy)
	if err != nil {
		return nil, fmt.Errorf("failed to get transport: %w")
	}

	return &http.Client{
		Transport: transport,
	}, nil
}

func GetHttpProxy() string {
	lock.RLock()
	defer lock.RUnlock()

	return httpProxyConfig
}

func GetHttpsProxy() string {
	lock.RLock()
	defer lock.RUnlock()

	return httpsProxyConfig
}
