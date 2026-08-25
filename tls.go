// Package main: tls.go — optional in-process TLS for the HTTP transport.
//
// By default the relay speaks plain HTTP and TLS is terminated by whatever
// fronts it (Caddy in the podman stack, an Ingress in Kubernetes). That stays
// the default. This file adds two opt-in ways to serve HTTPS from the binary
// itself, for deployments that have no reverse proxy to lean on:
//
//   - Manual: MCP_TLS_CERT + MCP_TLS_KEY point at a PEM certificate and key.
//     The pair is hot-reloaded on file change, so a cert-manager / certbot
//     renewal is picked up without a restart.
//
//   - ACME: MCP_TLS_ACME turns on automatic certificates via
//     golang.org/x/crypto/acme/autocert. MCP_TLS_ACME_DIRECTORY selects the
//     CA (default: Let's Encrypt production); a private ACME CA — e.g. the
//     step-ca the podman Caddyfile already uses — is reachable by pointing it
//     there and supplying that CA's roots via MCP_TLS_ACME_CA_ROOTS.
//     Challenges are served over TLS-ALPN-01 on the same :443 listener, so no
//     second port is needed.
//
// The two are mutually exclusive; configuring both is a startup error. Every
// failure mode here aborts startup loudly, matching newFetchACL / setProxy:
// a typo in a transport-security control must stop the server, not silently
// leave it on plain HTTP.
package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"sync"
	"time"

	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
)

// letsEncryptDirectory is the ACME directory used when MCP_TLS_ACME_DIRECTORY
// is unset. Production, not staging: an operator turning ACME on wants a
// browser-trusted certificate, and the staging CA's roots are not trusted.
const letsEncryptDirectory = "https://acme-v02.api.letsencrypt.org/directory"

// tlsSettings is the compiled TLS configuration. A nil *tlsSettings, or one
// whose tlsConfig is nil, means plain HTTP — the enabled() guard is nil-safe
// so callers never have to check both.
type tlsSettings struct {
	tlsConfig *tls.Config
	mode      string // "manual" | "acme", for the startup banner
	detail    string // banner detail: "cert+key (hot-reload)" or the ACME CA
}

// enabled reports whether HTTPS serving is configured.
func (t *tlsSettings) enabled() bool {
	return t != nil && t.tlsConfig != nil
}

// describe renders the TLS state for the startup banner.
func (t *tlsSettings) describe() string {
	if !t.enabled() {
		return "disabled (plain HTTP)"
	}
	return t.mode + " (" + t.detail + ")"
}

// newTLSSettings validates the MCP_TLS_* configuration and returns the built
// tls.Config, or (nil, nil) when no TLS is configured. Called from main()
// before the server starts; a returned error aborts startup.
func newTLSSettings(cfg Config) (*tlsSettings, error) {
	hasManual := cfg.TLSCertFile != "" || cfg.TLSKeyFile != ""
	hasACME := cfg.TLSACME

	switch {
	case !hasManual && !hasACME:
		return nil, nil
	case hasManual && hasACME:
		return nil, fmt.Errorf("TLS is over-configured: set EITHER MCP_TLS_CERT+MCP_TLS_KEY " +
			"(manual certificate) OR MCP_TLS_ACME (automatic certificates), not both")
	case hasManual:
		return newManualTLS(cfg)
	default:
		return newACMETLS(cfg)
	}
}

// newManualTLS builds the tls.Config for the operator-supplied cert/key pair.
// Both paths are required; the pair is loaded once here so a bad path or a
// mismatched cert/key fails startup rather than the first TLS handshake.
func newManualTLS(cfg Config) (*tlsSettings, error) {
	if cfg.TLSCertFile == "" || cfg.TLSKeyFile == "" {
		return nil, fmt.Errorf("manual TLS needs both MCP_TLS_CERT and MCP_TLS_KEY "+
			"(got cert=%q, key=%q)", cfg.TLSCertFile, cfg.TLSKeyFile)
	}
	r := &certReloader{certFile: cfg.TLSCertFile, keyFile: cfg.TLSKeyFile}
	if _, err := r.load(); err != nil {
		return nil, fmt.Errorf("MCP_TLS_CERT/MCP_TLS_KEY: %w", err)
	}
	return &tlsSettings{
		tlsConfig: &tls.Config{
			MinVersion:     tls.VersionTLS12,
			GetCertificate: r.getCertificate,
		},
		mode:   "manual",
		detail: "cert+key (hot-reload)",
	}, nil
}

// certReloader serves the manual cert/key pair through a GetCertificate
// callback, re-reading the files when their modification time changes. This
// makes an in-place renewal (cert-manager rewriting the mounted Secret,
// certbot's deploy hook) take effect on the next handshake without a restart.
type certReloader struct {
	certFile, keyFile string

	mu      sync.RWMutex
	cached  *tls.Certificate
	modCert time.Time
	modKey  time.Time
}

// getCertificate is the tls.Config.GetCertificate hook. It returns the cached
// certificate while the files are unchanged, and reloads when either mtime
// moves. A reload that fails mid-rotation (cert rewritten, key not yet, so the
// pair does not match) keeps serving the last good certificate rather than
// failing live handshakes.
func (r *certReloader) getCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	if c := r.currentIfFresh(); c != nil {
		return c, nil
	}
	c, err := r.load()
	if err != nil {
		if cached := r.current(); cached != nil {
			return cached, nil
		}
		return nil, err
	}
	return c, nil
}

// current returns the cached certificate under a read lock, or nil.
func (r *certReloader) current() *tls.Certificate {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.cached
}

// currentIfFresh returns the cached certificate when both files still carry
// the modification times it was loaded from, and nil when a reload is due. A
// stat error falls back to the cached cert so a transient FS hiccup does not
// drop a working certificate.
func (r *certReloader) currentIfFresh() *tls.Certificate {
	ci, errC := os.Stat(r.certFile)
	ki, errK := os.Stat(r.keyFile)
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.cached == nil {
		return nil
	}
	if errC != nil || errK != nil {
		return r.cached
	}
	if ci.ModTime().Equal(r.modCert) && ki.ModTime().Equal(r.modKey) {
		return r.cached
	}
	return nil
}

// load reads and parses the cert/key pair and caches it together with the
// modification times of the bytes it read, so currentIfFresh can detect the
// next change.
func (r *certReloader) load() (*tls.Certificate, error) {
	ci, err := os.Stat(r.certFile)
	if err != nil {
		return nil, err
	}
	ki, err := os.Stat(r.keyFile)
	if err != nil {
		return nil, err
	}
	cert, err := tls.LoadX509KeyPair(r.certFile, r.keyFile)
	if err != nil {
		return nil, err
	}
	r.mu.Lock()
	r.cached = &cert
	r.modCert = ci.ModTime()
	r.modKey = ki.ModTime()
	r.mu.Unlock()
	return &cert, nil
}

// newACMETLS builds the autocert-backed tls.Config. Certificates are obtained
// on demand for the allow-listed hostnames and cached on disk so they survive
// restarts. Challenges are answered over TLS-ALPN-01 on the same listener, so
// only :443 needs to be reachable.
func newACMETLS(cfg Config) (*tlsSettings, error) {
	if len(cfg.TLSACMEDomains) == 0 {
		return nil, fmt.Errorf("MCP_TLS_ACME is set but MCP_TLS_ACME_DOMAINS is empty: " +
			"name the hostname(s) the certificate should cover, e.g. \"relay.example.com\"")
	}
	if cfg.TLSACMECacheDir == "" {
		return nil, fmt.Errorf("MCP_TLS_ACME is set but MCP_TLS_ACME_CACHE_DIR is empty: " +
			"ACME needs a writable directory to persist issued certificates across restarts " +
			"(without it every restart re-requests certificates and can hit CA rate limits)")
	}
	if err := ensureWritableDir(cfg.TLSACMECacheDir); err != nil {
		return nil, fmt.Errorf("MCP_TLS_ACME_CACHE_DIR %q: %w", cfg.TLSACMECacheDir, err)
	}

	directory := cfg.TLSACMEDirectory
	caLabel := "letsencrypt"
	if directory == "" {
		directory = letsEncryptDirectory
	} else {
		if _, err := url.Parse(directory); err != nil {
			return nil, fmt.Errorf("MCP_TLS_ACME_DIRECTORY %q is not a valid URL: %w", directory, err)
		}
		caLabel = directory
	}

	client := &acme.Client{DirectoryURL: directory}
	if cfg.TLSACMECARoots != "" {
		httpClient, err := acmeHTTPClientWithRoots(cfg.TLSACMECARoots)
		if err != nil {
			return nil, fmt.Errorf("MCP_TLS_ACME_CA_ROOTS %q: %w", cfg.TLSACMECARoots, err)
		}
		client.HTTPClient = httpClient
	}

	m := &autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		HostPolicy: autocert.HostWhitelist(cfg.TLSACMEDomains...),
		Cache:      autocert.DirCache(cfg.TLSACMECacheDir),
		Email:      cfg.TLSACMEEmail,
		Client:     client,
	}
	tc := m.TLSConfig() // wires GetCertificate + the acme-tls/1 ALPN protocol
	tc.MinVersion = tls.VersionTLS12
	return &tlsSettings{
		tlsConfig: tc,
		mode:      "acme",
		detail:    caLabel,
	}, nil
}

// ensureWritableDir creates dir (0700) if absent and verifies it is writable
// by round-tripping a probe file, so an unwritable ACME cache is caught at
// startup rather than when the first certificate needs to be persisted.
func ensureWritableDir(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("cannot create directory: %w", err)
	}
	f, err := os.CreateTemp(dir, ".acme-write-probe-*")
	if err != nil {
		return fmt.Errorf("directory is not writable: %w", err)
	}
	name := f.Name()
	_ = f.Close()
	_ = os.Remove(name)
	return nil
}

// acmeHTTPClientWithRoots returns an HTTP client that trusts exactly the CA
// roots in pemPath, for talking to a private ACME directory (e.g. step-ca)
// whose own TLS certificate is not in the system trust store. It scopes the
// custom trust to the ACME client only; it does not affect the fetch tool or
// the SearXNG client.
func acmeHTTPClientWithRoots(pemPath string) (*http.Client, error) {
	pemBytes, err := os.ReadFile(pemPath)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pemBytes) {
		return nil, fmt.Errorf("no PEM certificates found in file")
	}
	return &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig:     &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
			TLSHandshakeTimeout: 10 * time.Second,
		},
	}, nil
}
