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
//   - ACME: automatic certificates via golang.org/x/crypto/acme/autocert.
//     There is no on/off flag — setting any MCP_TLS_ACME_* variable turns
//     ACME on, and MCP_TLS_ACME_DOMAINS (the hostnames to certify) is then
//     required, so a half-configured ACME setup fails loudly rather than
//     silently serving plain HTTP. MCP_TLS_ACME_DIRECTORY selects the CA
//     (default: Let's Encrypt production); a private ACME CA — e.g. the
//     step-ca the podman Caddyfile already uses — is reachable by pointing it
//     there. That CA's own directory-endpoint certificate is trusted through
//     the process trust store by default (mount the CA there, or set
//     SSL_CERT_FILE); MCP_TLS_ACME_CA_ROOTS is an optional override that
//     confines that trust to the ACME client alone, keeping it out of the
//     fetch tool and SearXNG paths. Issued certificates are cached under
//     MCP_TLS_ACME_CACHE_DIR (default /var/cache/mcp-acme — mount a volume,
//     bind mount or PVC there so they persist across restarts). Challenges are
//     served over TLS-ALPN-01 on the same :443 listener, so no second port is
//     needed.
//
// Manual and ACME are mutually exclusive; configuring both is a startup error.
// Every failure mode here aborts startup loudly, matching newFetchACL /
// setProxy: a typo in a transport-security control must stop the server, not
// silently leave it on plain HTTP.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log/slog"
	"net/http"
	"net/mail"
	"net/url"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
)

// letsEncryptDirectory is the ACME directory used when MCP_TLS_ACME_DIRECTORY
// is unset. Production, not staging: an operator turning ACME on wants a
// browser-trusted certificate, and the staging CA's roots are not trusted.
const letsEncryptDirectory = "https://acme-v02.api.letsencrypt.org/directory"

// defaultACMECacheDir is where issued certificates are cached when
// MCP_TLS_ACME_CACHE_DIR is unset. It must resolve to a writable, persistent
// location — mount a volume, bind mount or PVC there — or restarts re-request
// certificates and can hit CA rate limits. ensureWritableDir fails startup
// when it is not writable (the usual read-only-rootfs case), so the operator
// is told to mount something rather than silently getting an ephemeral cache.
const defaultACMECacheDir = "/var/cache/mcp-acme"

// acmeConfigured reports whether the operator is asking for ACME at all. ACME
// has no on/off flag: naming the domain(s) — or setting any other
// MCP_TLS_ACME_* parameter — turns it on. newTLSSettings then requires
// MCP_TLS_ACME_DOMAINS within that mode, so a stray or half-configured ACME
// variable fails startup loudly instead of silently serving plain HTTP.
func acmeConfigured(cfg Config) bool {
	return len(cfg.TLSACMEDomains) > 0 ||
		cfg.TLSACMEEmail != "" ||
		cfg.TLSACMEDirectory != "" ||
		cfg.TLSACMECacheDir != "" ||
		cfg.TLSACMECARoots != ""
}

// tlsSettings is the compiled TLS configuration. A nil *tlsSettings, or one
// whose tlsConfig is nil, means plain HTTP — the enabled() guard is nil-safe
// so callers never have to check both.
type tlsSettings struct {
	tlsConfig *tls.Config
	mode      string // "manual" | "acme", for the startup banner
	detail    string // banner detail: "cert+key (hot-reload)" or the ACME CA

	// ACME-only observability/warmup state (nil/zero in manual and plain
	// modes). autocert obtains certificates lazily on the first matching
	// handshake and logs nothing, so an operator watching a freshly started
	// relay sees no ACME traffic and no log lines. These let main() warm the
	// certificates at startup and log exactly what ACME is doing.
	acmeManager   *autocert.Manager
	acmeDomains   []string
	acmeDirectory string // resolved directory URL (default filled in)
	acmeCacheDir  string // resolved cache dir (default filled in)
	acmeEmailSet  bool   // whether a contact email was configured
	acmeCAScoped  bool   // whether MCP_TLS_ACME_CA_ROOTS confined CA trust
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
	hasACME := acmeConfigured(cfg)

	switch {
	case !hasManual && !hasACME:
		return nil, nil
	case hasManual && hasACME:
		return nil, fmt.Errorf("TLS is over-configured: set EITHER MCP_TLS_CERT+MCP_TLS_KEY " +
			"(manual certificate) OR the MCP_TLS_ACME_* variables (automatic certificates), not both")
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
		return nil, fmt.Errorf("ACME is configured but MCP_TLS_ACME_DOMAINS is empty: " +
			"name the hostname(s) the certificate should cover, e.g. \"relay.example.com\"")
	}

	// MCP_TLS_ACME_EMAIL is optional — ACME registers without a contact when it
	// is unset. But a value that is set must be a bare, well-formed address: a
	// public CA (Let's Encrypt) rejects a malformed contact at account
	// registration, which would otherwise surface only at first issuance, not
	// startup. This is a shape check; the CA remains the final authority.
	if cfg.TLSACMEEmail != "" {
		if addr, err := mail.ParseAddress(cfg.TLSACMEEmail); err != nil || addr.Address != cfg.TLSACMEEmail {
			return nil, fmt.Errorf("MCP_TLS_ACME_EMAIL %q is not a valid email address: "+
				"give a bare address like \"admin@example.com\", or leave it unset to "+
				"register without a contact", cfg.TLSACMEEmail)
		}
	}

	// MCP_TLS_ACME_CACHE_DIR is optional and defaults to a well-known path; the
	// operator's job is to make that path persistent (a volume/bind mount/PVC),
	// not to name it. ensureWritableDir turns an unwritable cache — the common
	// read-only-rootfs case when nothing is mounted there — into a loud startup
	// error rather than a silently ephemeral cache that re-requests every boot.
	cacheDir := cfg.TLSACMECacheDir
	if cacheDir == "" {
		cacheDir = defaultACMECacheDir
	}
	if err := ensureWritableDir(cacheDir); err != nil {
		return nil, fmt.Errorf("MCP_TLS_ACME_CACHE_DIR %q: %w "+
			"(mount a volume, bind mount or PVC there so issued certificates persist across restarts)",
			cacheDir, err)
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
	caScoped := false
	if cfg.TLSACMECARoots != "" {
		httpClient, err := acmeHTTPClientWithRoots(cfg.TLSACMECARoots)
		if err != nil {
			return nil, fmt.Errorf("MCP_TLS_ACME_CA_ROOTS %q: %w", cfg.TLSACMECARoots, err)
		}
		client.HTTPClient = httpClient
		caScoped = true
	}

	m := &autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		HostPolicy: autocert.HostWhitelist(cfg.TLSACMEDomains...),
		Cache:      autocert.DirCache(cacheDir),
		Email:      cfg.TLSACMEEmail,
		Client:     client,
	}
	tc := m.TLSConfig() // wires GetCertificate + the acme-tls/1 ALPN protocol
	tc.MinVersion = tls.VersionTLS12
	// autocert emits no logs of its own, so wrap the certificate hook to make
	// every handshake and every issuance failure visible (see logGetCertificate).
	tc.GetCertificate = logGetCertificate(tc.GetCertificate)
	return &tlsSettings{
		tlsConfig:     tc,
		mode:          "acme",
		detail:        caLabel,
		acmeManager:   m,
		acmeDomains:   cfg.TLSACMEDomains,
		acmeDirectory: directory,
		acmeCacheDir:  cacheDir,
		acmeEmailSet:  cfg.TLSACMEEmail != "",
		acmeCAScoped:  caScoped,
	}, nil
}

// logGetCertificate wraps an ACME GetCertificate hook so the otherwise-silent
// ACME path is observable. Every handshake — ordinary ones and the acme-tls/1
// challenge handshakes the CA makes — is logged at debug, and any failure to
// serve or obtain a certificate (an unreachable directory, a hostname outside
// the allow-list, a failed challenge) is surfaced at warn. Without this an
// operator has no way to see what autocert is doing or why a certificate is
// not appearing.
func logGetCertificate(inner func(*tls.ClientHelloInfo) (*tls.Certificate, error)) func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	return func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		challenge := slices.Contains(hello.SupportedProtos, acme.ALPNProto)
		var remote string
		if hello.Conn != nil {
			remote = hello.Conn.RemoteAddr().String()
		}
		slog.Debug("acme: tls handshake",
			"sni", hello.ServerName, "challenge", challenge, "remote", remote)
		cert, err := inner(hello)
		if err != nil {
			slog.Warn("acme: no certificate served for handshake",
				"sni", hello.ServerName, "challenge", challenge, "remote", remote, "error", err)
			return nil, err
		}
		return cert, nil
	}
}

// logStartup records the effective TLS configuration once at boot. The banner
// carries a one-line summary; this adds the ACME specifics an operator needs
// when a certificate is not appearing — which directory is being hit, for
// which hosts, where issued certs are cached, whether a contact email was
// accepted, and how the directory's own CA is trusted — at info level so it
// shows without enabling debug.
func (t *tlsSettings) logStartup() {
	if t == nil || t.acmeManager == nil {
		return
	}
	trust := "process trust store"
	if t.acmeCAScoped {
		trust = "scoped to acme client (MCP_TLS_ACME_CA_ROOTS)"
	}
	slog.Info("acme: enabled",
		"directory", t.acmeDirectory,
		"domains", strings.Join(t.acmeDomains, ","),
		"cache_dir", t.acmeCacheDir,
		"email_set", t.acmeEmailSet,
		"ca_trust", trust)
}

// warmACME proactively obtains a certificate for each configured host at
// startup, instead of waiting for the first client handshake. autocert is
// lazy: with nothing warming it, the CA is never contacted until a real
// request with a matching SNI arrives, which is what leaves an operator
// staring at a silent ACME server and an empty relay log. Each obtain drives a
// TLS-ALPN-01 challenge against the running listener, so this must be called
// only after the server is serving. Failures are logged, never fatal — a
// transient DNS or reachability problem should not take the process down, and
// the next real handshake (or restart) retries.
func (t *tlsSettings) warmACME(ctx context.Context) {
	if t == nil || t.acmeManager == nil {
		return
	}
	for _, host := range t.acmeDomains {
		if ctx.Err() != nil {
			return
		}
		slog.Info("acme: requesting certificate", "host", host, "directory", t.acmeDirectory)
		start := time.Now()
		if _, err := t.acmeManager.GetCertificate(&tls.ClientHelloInfo{ServerName: host}); err != nil {
			// The most common failure is the CA being unable to reach back for
			// the challenge. TLS-ALPN-01 is validated by the CA connecting to
			// the host on tcp/443 (fixed by RFC 8737, regardless of the port
			// the relay listens on), so surface that requirement here — an
			// "acme:error:connection / could not connect to validation target"
			// almost always means <host>:443 is not reachable from the CA.
			slog.Warn("acme: certificate request failed",
				"host", host, "directory", t.acmeDirectory,
				"elapsed", time.Since(start).Round(time.Millisecond).String(), "error", err,
				"hint", "the CA must reach "+host+" on tcp/443 to validate the TLS-ALPN-01 challenge (check DNS, port-443 routing, and firewall)")
			continue
		}
		slog.Info("acme: certificate ready",
			"host", host, "elapsed", time.Since(start).Round(time.Millisecond).String())
	}
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
