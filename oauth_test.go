package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	oidc "github.com/coreos/go-oidc/v3/oidc"
	jose "github.com/go-jose/go-jose/v4"
	jwt "github.com/go-jose/go-jose/v4/jwt"
)

// oidcTestContext scopes discovery/JWKS fetching to the httptest server's own
// client, which trusts its self-signed certificate — the same hook production
// uses to inject a private CA's roots.
func oidcTestContext(srv *httptest.Server) context.Context {
	return oidc.ClientContext(context.Background(), srv.Client())
}

func containsResourceMetadata(wwwAuthenticate string) bool {
	return strings.Contains(wwwAuthenticate, "resource_metadata=")
}

const (
	oauthTestIssuer = "https://issuer.test"
	oauthTestAud    = "https://relay.test"
)

func oauthTestKey(t *testing.T, kid string) (*rsa.PrivateKey, jose.JSONWebKey) {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return k, jose.JSONWebKey{Key: &k.PublicKey, KeyID: kid, Algorithm: string(jose.RS256), Use: "sig"}
}

func oauthSignToken(t *testing.T, priv *rsa.PrivateKey, kid string, claims map[string]any) string {
	t.Helper()
	sig, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: priv},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", kid),
	)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := jwt.Signed(sig).Claims(claims).Serialize()
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func oauthWriteJWKS(t *testing.T, path string, keys ...jose.JSONWebKey) {
	t.Helper()
	b, err := json.Marshal(jose.JSONWebKeySet{Keys: keys})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
}

func oauthBaseClaims() map[string]any {
	return map[string]any{
		"iss":   oauthTestIssuer,
		"aud":   oauthTestAud,
		"sub":   "user-123",
		"scope": "search read",
		"exp":   time.Now().Add(time.Hour).Unix(),
		"iat":   time.Now().Unix(),
	}
}

// fileModeSettings builds an OAuth verifier in static-JWKS-file mode (no
// network) for tests, through the real newOAuthSettings constructor.
func fileModeSettings(t *testing.T, jwksPath string, extra map[string]string) *oauthSettings {
	t.Helper()
	cfg := Config{
		OAuthIssuer:   oauthTestIssuer,
		OAuthAudience: oauthTestAud,
		OAuthJWKSFile: jwksPath,
	}
	cfg.OAuthIdentityClaim = extra["identity_claim"]
	cfg.OAuthRequiredScope = extra["required_scope"]
	o, err := newOAuthSettings(context.Background(), cfg)
	if err != nil {
		t.Fatalf("newOAuthSettings: %v", err)
	}
	if !o.enabled() {
		t.Fatal("expected OAuth to be enabled")
	}
	return o
}

// ── newOAuthSettings validation matrix ────────────────────────────────────────

func TestNewOAuthSettings_OffByDefault(t *testing.T) {
	o, err := newOAuthSettings(context.Background(), Config{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if o.enabled() {
		t.Fatal("OAuth should be off with no MCP_OAUTH_* set")
	}
}

func TestNewOAuthSettings_HalfConfiguredFails(t *testing.T) {
	// Audience without issuer is a mistake that must not silently no-op.
	if _, err := newOAuthSettings(context.Background(), Config{OAuthAudience: oauthTestAud}); err == nil {
		t.Fatal("expected error when MCP_OAUTH_AUDIENCE is set without an issuer")
	}
}

func TestNewOAuthSettings_MissingAudienceFails(t *testing.T) {
	if _, err := newOAuthSettings(context.Background(), Config{OAuthIssuer: oauthTestIssuer}); err == nil {
		t.Fatal("expected error when issuer is set without an audience")
	}
}

func TestNewOAuthSettings_BadIssuerURLFails(t *testing.T) {
	cfg := Config{OAuthIssuer: "not-a-url", OAuthAudience: oauthTestAud}
	if _, err := newOAuthSettings(context.Background(), cfg); err == nil {
		t.Fatal("expected error for a non-absolute issuer URL")
	}
}

func TestNewOAuthSettings_UnreadableJWKSFileFails(t *testing.T) {
	cfg := Config{
		OAuthIssuer:   oauthTestIssuer,
		OAuthAudience: oauthTestAud,
		OAuthJWKSFile: filepath.Join(t.TempDir(), "does-not-exist.json"),
	}
	if _, err := newOAuthSettings(context.Background(), cfg); err == nil {
		t.Fatal("expected error for a missing JWKS file")
	}
}

// ── file mode: verification, claims, hot reload ───────────────────────────────

func TestOAuthFileMode_VerifyAndClaims(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "jwks.json")
	priv, pub := oauthTestKey(t, "k1")
	oauthWriteJWKS(t, path, pub)

	o := fileModeSettings(t, path, nil)
	ctx := context.Background()

	id, err := o.Verify(ctx, oauthSignToken(t, priv, "k1", oauthBaseClaims()))
	if err != nil {
		t.Fatalf("valid token rejected: %v", err)
	}
	if id != "user-123" {
		t.Fatalf("identity = %q, want the sub", id)
	}

	// Wrong audience.
	bad := oauthBaseClaims()
	bad["aud"] = "https://elsewhere.test"
	if _, err := o.Verify(ctx, oauthSignToken(t, priv, "k1", bad)); err == nil {
		t.Fatal("token for another audience was accepted")
	}

	// Expired.
	exp := oauthBaseClaims()
	exp["exp"] = time.Now().Add(-time.Minute).Unix()
	if _, err := o.Verify(ctx, oauthSignToken(t, priv, "k1", exp)); err == nil {
		t.Fatal("expired token was accepted")
	}
}

func TestOAuthFileMode_CustomIdentityClaim(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "jwks.json")
	priv, pub := oauthTestKey(t, "k1")
	oauthWriteJWKS(t, path, pub)

	o := fileModeSettings(t, path, map[string]string{"identity_claim": "email"})
	claims := oauthBaseClaims()
	claims["email"] = "alice@example.com"

	id, err := o.Verify(context.Background(), oauthSignToken(t, priv, "k1", claims))
	if err != nil {
		t.Fatalf("valid token rejected: %v", err)
	}
	if id != "alice@example.com" {
		t.Fatalf("identity = %q, want the email claim", id)
	}
}

func TestOAuthFileMode_RequiredScope(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "jwks.json")
	priv, pub := oauthTestKey(t, "k1")
	oauthWriteJWKS(t, path, pub)

	o := fileModeSettings(t, path, map[string]string{"required_scope": "admin"})

	// Token without the scope is rejected.
	if _, err := o.Verify(context.Background(), oauthSignToken(t, priv, "k1", oauthBaseClaims())); err == nil {
		t.Fatal("token missing the required scope was accepted")
	}
	// Token with the scope passes.
	ok := oauthBaseClaims()
	ok["scope"] = "search admin"
	if _, err := o.Verify(context.Background(), oauthSignToken(t, priv, "k1", ok)); err != nil {
		t.Fatalf("token with required scope rejected: %v", err)
	}
}

func TestOAuthFileMode_HotReload(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "jwks.json")
	priv1, pub1 := oauthTestKey(t, "k1")
	oauthWriteJWKS(t, path, pub1)

	o := fileModeSettings(t, path, nil)
	ctx := context.Background()

	if _, err := o.Verify(ctx, oauthSignToken(t, priv1, "k1", oauthBaseClaims())); err != nil {
		t.Fatalf("token from initial key rejected: %v", err)
	}

	// Rotate the JWKS file to a new key; bump mtime so the change is detected.
	priv2, pub2 := oauthTestKey(t, "k2")
	oauthWriteJWKS(t, path, pub2)
	future := time.Now().Add(2 * time.Second)
	if err := os.Chtimes(path, future, future); err != nil {
		t.Fatal(err)
	}

	if _, err := o.Verify(ctx, oauthSignToken(t, priv1, "k1", oauthBaseClaims())); err == nil {
		t.Fatal("token from the retired key still verified after rotation")
	}
	if _, err := o.Verify(ctx, oauthSignToken(t, priv2, "k2", oauthBaseClaims())); err != nil {
		t.Fatalf("token from the rotated-in key rejected: %v", err)
	}
}

// ── issuer discovery mode ─────────────────────────────────────────────────────

func TestOAuthIssuerMode_Discovery(t *testing.T) {
	priv, pub := oauthTestKey(t, "kA")

	mux := http.NewServeMux()
	var srv *httptest.Server
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                 srv.URL,
			"jwks_uri":               srv.URL + "/jwks",
			"authorization_endpoint": srv.URL + "/authorize",
			"token_endpoint":         srv.URL + "/token",
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{pub}})
	})
	srv = httptest.NewServer(mux)
	defer srv.Close()

	// The httptest server uses a self-signed cert only its own client trusts;
	// oidc reaches it through the client we scope in via the discovery context.
	cfg := Config{OAuthIssuer: srv.URL, OAuthAudience: oauthTestAud}
	o, err := newOAuthSettings(oidcTestContext(srv), cfg)
	if err != nil {
		t.Fatalf("discovery failed: %v", err)
	}

	claims := oauthBaseClaims()
	claims["iss"] = srv.URL
	id, err := o.Verify(context.Background(), oauthSignToken(t, priv, "kA", claims))
	if err != nil {
		t.Fatalf("valid token rejected in issuer mode: %v", err)
	}
	if id != "user-123" {
		t.Fatalf("identity = %q", id)
	}
	if o.mode != "issuer" {
		t.Fatalf("mode = %q, want issuer", o.mode)
	}
}

// ── requireAuth: coexistence of static tokens and OAuth ───────────────────────

func TestRequireAuth_StaticAndOAuthCoexist(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "jwks.json")
	priv, pub := oauthTestKey(t, "k1")
	oauthWriteJWKS(t, path, pub)
	oauth := fileModeSettings(t, path, nil)

	staticTok := "0123456789abcdef0123456789abcdef"
	digest := sha256.Sum256([]byte("Bearer " + staticTok))
	s := &Server{config: Config{
		AuthTokens: map[tokenDigest]string{digest: "static-alice"},
		OAuth:      oauth,
	}}

	var gotIdentity string
	h := s.requireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotIdentity = identityFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	}))

	// Static token → static identity.
	gotIdentity = ""
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req.Header.Set("Authorization", "Bearer "+staticTok)
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK || gotIdentity != "static-alice" {
		t.Fatalf("static token: code=%d identity=%q", rr.Code, gotIdentity)
	}

	// OAuth JWT → identity from the token.
	gotIdentity = ""
	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/", nil)
	req.Header.Set("Authorization", "Bearer "+oauthSignToken(t, priv, "k1", oauthBaseClaims()))
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK || gotIdentity != "user-123" {
		t.Fatalf("oauth token: code=%d identity=%q", rr.Code, gotIdentity)
	}

	// Garbage token → 401 with a resource_metadata challenge.
	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/", nil)
	req.Header.Set("Authorization", "Bearer not-a-jwt")
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("garbage token: code=%d, want 401", rr.Code)
	}
	if wa := rr.Header().Get("WWW-Authenticate"); !containsResourceMetadata(wa) {
		t.Fatalf("WWW-Authenticate = %q, want a resource_metadata parameter", wa)
	}
}

func TestRequireAuth_OpenWhenNothingConfigured(t *testing.T) {
	s := &Server{config: Config{}} // no static tokens, no OAuth
	called := false
	h := s.requireAuth(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/", nil))
	if !called || rr.Code != http.StatusOK {
		t.Fatalf("expected open pass-through, got code=%d called=%v", rr.Code, called)
	}
}

// ── metadata endpoint ─────────────────────────────────────────────────────────

func TestHandleOAuthMetadata(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "jwks.json")
	_, pub := oauthTestKey(t, "k1")
	oauthWriteJWKS(t, path, pub)
	s := &Server{config: Config{OAuth: fileModeSettings(t, path, nil)}}

	rr := httptest.NewRecorder()
	s.handleOAuthMetadata(rr, httptest.NewRequest(http.MethodGet, oauthMetadataPath, nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("code = %d", rr.Code)
	}
	var doc map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if doc["resource"] != oauthTestAud {
		t.Fatalf("resource = %v, want the audience", doc["resource"])
	}
	as, ok := doc["authorization_servers"].([]any)
	if !ok || len(as) != 1 || as[0] != oauthTestIssuer {
		t.Fatalf("authorization_servers = %v, want [issuer]", doc["authorization_servers"])
	}
}

func TestHandleOAuthMetadata_NotFoundWhenDisabled(t *testing.T) {
	s := &Server{config: Config{}} // OAuth nil
	rr := httptest.NewRecorder()
	s.handleOAuthMetadata(rr, httptest.NewRequest(http.MethodGet, oauthMetadataPath, nil))
	if rr.Code != http.StatusNotFound {
		t.Fatalf("code = %d, want 404 when OAuth is off", rr.Code)
	}
}

// ── helpers ───────────────────────────────────────────────────────────────────

func TestBearerToken(t *testing.T) {
	cases := map[string]string{
		"Bearer abc":  "abc",
		"bearer abc":  "abc", // case-insensitive scheme
		"BEARER  abc": "abc", // trimmed
		"Basic abc":   "",
		"":            "",
		"Bearer":      "",
	}
	for in, want := range cases {
		if got := bearerToken(in); got != want {
			t.Errorf("bearerToken(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestResourceMetadataURL_HonoursForwardedHeaders(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "http://internal:8080/", nil)
	req.Host = "internal:8080"
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("X-Forwarded-Host", "relay.example.com")
	got := resourceMetadataURL(req)
	want := "https://relay.example.com" + oauthMetadataPath
	if got != want {
		t.Fatalf("resourceMetadataURL = %q, want %q", got, want)
	}
}
