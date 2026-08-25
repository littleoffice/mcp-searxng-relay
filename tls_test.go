package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// ── helpers ───────────────────────────────────────────────────────────────────

// writeSelfSigned generates a self-signed ECDSA certificate covering localhost
// + 127.0.0.1 and writes the cert and key PEM files into dir, returning their
// paths. serial distinguishes two otherwise-identical certs so a hot-reload
// test can tell which one is being served. Generating in-test keeps committed
// key material out of the repo, matching the fence-key suite.
func writeSelfSigned(t *testing.T, dir string, serial int64) (certPath, keyPath string, der []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(serial),
		Subject:               pkix.Name{CommonName: "localhost"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.IPv4(127, 0, 0, 1)},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err = x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("creating certificate: %v", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshalling key: %v", err)
	}

	certPath = filepath.Join(dir, "cert.pem")
	keyPath = filepath.Join(dir, "key.pem")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatalf("writing cert: %v", err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatalf("writing key: %v", err)
	}
	return certPath, keyPath, der
}

// ── newTLSSettings: validation ────────────────────────────────────────────────

func TestNewTLSSettings_Validation(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath, _ := writeSelfSigned(t, dir, 1)
	cacheDir := filepath.Join(dir, "acme-cache")

	tests := []struct {
		name       string
		cfg        Config
		wantMode   string // "" means expect (nil, nil)
		wantDetail string // checked only when wantMode != ""
		wantErr    bool
	}{
		{name: "nothing configured", cfg: Config{}},
		{
			name:    "manual and acme together",
			cfg:     Config{TLSCertFile: certPath, TLSKeyFile: keyPath, TLSACME: true, TLSACMEDomains: []string{"x"}, TLSACMECacheDir: cacheDir},
			wantErr: true,
		},
		{name: "cert without key", cfg: Config{TLSCertFile: certPath}, wantErr: true},
		{name: "key without cert", cfg: Config{TLSKeyFile: keyPath}, wantErr: true},
		{name: "manual with missing cert file", cfg: Config{TLSCertFile: filepath.Join(dir, "nope.pem"), TLSKeyFile: keyPath}, wantErr: true},
		{
			name:       "valid manual",
			cfg:        Config{TLSCertFile: certPath, TLSKeyFile: keyPath},
			wantMode:   "manual",
			wantDetail: "cert+key (hot-reload)",
		},
		{name: "acme without domains", cfg: Config{TLSACME: true, TLSACMECacheDir: cacheDir}, wantErr: true},
		{name: "acme without cache dir", cfg: Config{TLSACME: true, TLSACMEDomains: []string{"x"}}, wantErr: true},
		{
			name:       "valid acme defaults to lets encrypt",
			cfg:        Config{TLSACME: true, TLSACMEDomains: []string{"relay.example.com"}, TLSACMECacheDir: cacheDir},
			wantMode:   "acme",
			wantDetail: "letsencrypt",
		},
		{
			name:       "acme with custom directory reports it",
			cfg:        Config{TLSACME: true, TLSACMEDomains: []string{"relay.example.com"}, TLSACMECacheDir: cacheDir, TLSACMEDirectory: "https://ca.internal/acme/directory"},
			wantMode:   "acme",
			wantDetail: "https://ca.internal/acme/directory",
		},
		{
			name:    "acme with invalid directory url",
			cfg:     Config{TLSACME: true, TLSACMEDomains: []string{"x"}, TLSACMECacheDir: cacheDir, TLSACMEDirectory: "://missing-scheme"},
			wantErr: true,
		},
		{
			name:    "acme with unreadable ca roots",
			cfg:     Config{TLSACME: true, TLSACMEDomains: []string{"x"}, TLSACMECacheDir: cacheDir, TLSACMECARoots: filepath.Join(dir, "no-such-roots.pem")},
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := newTLSSettings(tc.cfg)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got settings %+v", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tc.wantMode == "" {
				if got.enabled() {
					t.Fatalf("expected TLS disabled, got mode %q", got.mode)
				}
				return
			}
			if !got.enabled() {
				t.Fatal("expected TLS enabled")
			}
			if got.mode != tc.wantMode {
				t.Errorf("mode = %q, want %q", got.mode, tc.wantMode)
			}
			if got.detail != tc.wantDetail {
				t.Errorf("detail = %q, want %q", got.detail, tc.wantDetail)
			}
		})
	}
}

// ── certReloader: hot reload ──────────────────────────────────────────────────

// Rewriting the cert/key files must change the served certificate without a
// process restart — this is what makes an in-place cert-manager/certbot
// renewal take effect. Serial numbers distinguish the two certs.
func TestCertReloader_HotReload(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath, derA := writeSelfSigned(t, dir, 1001)

	r := &certReloader{certFile: certPath, keyFile: keyPath}
	first, err := r.getCertificate(nil)
	if err != nil {
		t.Fatalf("first getCertificate: %v", err)
	}
	if string(first.Certificate[0]) != string(derA) {
		t.Fatal("first load did not serve cert A")
	}

	// Overwrite with a second cert and push the mtimes forward so the freshness
	// check reliably detects the change even on coarse-resolution filesystems.
	_, _, derB := writeSelfSigned(t, dir, 1002)
	future := time.Now().Add(2 * time.Second)
	for _, p := range []string{certPath, keyPath} {
		if err := os.Chtimes(p, future, future); err != nil {
			t.Fatalf("chtimes %s: %v", p, err)
		}
	}

	second, err := r.getCertificate(nil)
	if err != nil {
		t.Fatalf("second getCertificate: %v", err)
	}
	if string(second.Certificate[0]) != string(derB) {
		t.Fatal("did not reload cert B after files changed")
	}
	if string(second.Certificate[0]) == string(derA) {
		t.Fatal("still serving cert A after reload")
	}
}

// ── manual TLS: end to end ────────────────────────────────────────────────────

// The tls.Config built for manual mode must actually complete a handshake and
// serve a request when a client trusts the certificate.
func TestManualTLS_ServesHTTPS(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath, der := writeSelfSigned(t, dir, 2001)

	settings, err := newTLSSettings(Config{TLSCertFile: certPath, TLSKeyFile: keyPath})
	if err != nil {
		t.Fatalf("newTLSSettings: %v", err)
	}

	ln, err := tls.Listen("tcp", "127.0.0.1:0", settings.tlsConfig)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ok")
	})}
	go func() { _ = srv.Serve(ln) }()
	defer func() { _ = srv.Shutdown(context.Background()) }()

	// Trust exactly the self-signed cert we generated.
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	client := &http.Client{
		Timeout:   5 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}},
	}

	resp, err := client.Get("https://" + ln.Addr().String() + "/health")
	if err != nil {
		t.Fatalf("GET over TLS: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || string(body) != "ok" {
		t.Fatalf("got %d %q, want 200 \"ok\"", resp.StatusCode, body)
	}
}

// ── acme HostPolicy wiring ────────────────────────────────────────────────────

// The ACME tls.Config must refuse a handshake for a hostname outside
// MCP_TLS_ACME_DOMAINS, proving the HostWhitelist reached the manager. An
// allow-listed name proceeds past the policy check (and then fails trying to
// reach the fake CA, which is fine — we only assert the policy boundary).
func TestACME_HostPolicyEnforced(t *testing.T) {
	settings, err := newTLSSettings(Config{
		TLSACME:          true,
		TLSACMEDomains:   []string{"allowed.example.com"},
		TLSACMECacheDir:  filepath.Join(t.TempDir(), "cache"),
		TLSACMEDirectory: "https://127.0.0.1:1/acme/directory", // unreachable on purpose
	})
	if err != nil {
		t.Fatalf("newTLSSettings: %v", err)
	}

	getCert := settings.tlsConfig.GetCertificate
	if getCert == nil {
		t.Fatal("ACME tls.Config has no GetCertificate hook")
	}

	_, err = getCert(&tls.ClientHelloInfo{ServerName: "blocked.example.com"})
	if err == nil {
		t.Fatal("expected HostPolicy to reject a non-allow-listed hostname")
	}
}

// ── describe / label ──────────────────────────────────────────────────────────

func TestTLSSettings_Describe(t *testing.T) {
	if got := (*tlsSettings)(nil).describe(); got != "disabled (plain HTTP)" {
		t.Errorf("nil describe = %q", got)
	}
	if got := tlsModeLabel("stdio", nil); got == "" || got == "disabled (plain HTTP)" {
		t.Errorf("stdio label should be n/a, got %q", got)
	}
	s := &tlsSettings{tlsConfig: &tls.Config{}, mode: "manual", detail: "cert+key (hot-reload)"}
	if got := tlsModeLabel("streamable-http", s); got != "manual (cert+key (hot-reload))" {
		t.Errorf("http label = %q", got)
	}
}
