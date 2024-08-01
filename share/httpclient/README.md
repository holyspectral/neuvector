# HTTP client

This package provides common http.Transport(s)/connection pools to be used by NV. To use this package, follow below steps:

## Implement config update callback.

When proxy or TLS config is changed, SetDefaultTLSClientConfig() should be called.  For example, the below snippet parses config and set the default TLS config.

```
		var pool *x509.CertPool

		if cfg.GlobalCaCerts != "" {
			pool = x509.NewCertPool()
			pool.AppendCertsFromPEM([]byte(cfg.GlobalCaCerts))
		}

		httpProxy := httpclient.ParseProxy(&cfg.RegistryHttpProxy)
		httpsProxy := httpclient.ParseProxy(&cfg.RegistryHttpsProxy)
		var noProxy string

		httpclient.SetDefaultTLSClientConfig(&httpclient.TLSClientSettings{
			TLSconfig: &tls.Config{
				InsecureSkipVerify: !cfg.EnableTLSVerification,
				RootCAs:            pool,
			},
		}, httpProxy, httpsProxy, noProxy)
```

## http.Client implementation

Due to different implementations of http clients, this package provides three methods to share http.Transport.

### GetSharedTransport() and GetNoProxySharedTransport()

In NeuVector, proxy can be enabled/disabled in per-resource based.  For example, each registry can have different setting even when they connect to the same endpoints.  To utilize this package, use code similar to the snippet below:

```
if proxy != "" {
    client.Transport = httpclient.GetSharedTransport()
} else {
    client.Transport = httpclient.GetNoProxySharedTransport()
}
```

This way, the shared http.Transport will be used depending on each function's proxy setting.

### GetTLSConfig()

In some connections that are based on TLS but not HTTP, you can still utilize the shared TLSConfig by using the code below:

```
    // Copy from LDAP implementation
    err = l.StartTLS(httpclient.GetTLSConfig())
    if err != nil {
        return err
    }
```

Note that when with this method, proxy settings will not be honored. 

### CreateHTTPClient()/CreateNoProxyHTTPClient()

If there is no strong preference on HTTP client setting, developers can use `httpclient.CreateHTTPClient()` and `httpclient.CreateNoProxyHTTPClient()` to create a HTTP client using the default setting.

```
	client := httpclient.CreateHTTPClient()
```

## Reference

https://pkg.go.dev/net/http#Transport

> Transports should be reused instead of created as needed. Transports are safe for concurrent use by multiple goroutines.

