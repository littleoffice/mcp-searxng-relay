// Package main: oauth.go — optional OAuth 2.0 / OIDC bearer-token verification.
//
// By default the relay authenticates callers against the static token table
// built by parseAuthTokens (MCP_AUTH_TOKEN*), where the operator mints an
// opaque secret out-of-band and labels it with an identity. That stays the
// default. This file adds an opt-in second path: instead of matching a shared
// secret, verify a JSON Web Token that an external OAuth 2.0 / OIDC provider
// (Keycloak, Auth0, Entra, Dex, …) issued for this relay, and derive the audit
// identity from one of its claims.
//
// The relay is a Resource Server, never an Authorization Server: it does not
// run /authorize or /token, has no consent screen, and stores no refresh
// tokens. The provider owns the whole token lifecycle; this file only
// *verifies* a presented token's signature and claims. That is why the
// structural footprint is small — verification replaces the "bearer string →
// identity" lookup step in requireAuth, and every downstream concern (audit
// logging, rate limiting, history) keeps keying off the identity string it
// already used.
//
// Two mutually-exclusive key sources, mirroring the manual-vs-discovered split
// used elsewhere for transport security:
//
//   - Issuer discovery (default): MCP_OAUTH_ISSUER names an OIDC issuer whose
//     /.well-known/openid-configuration and JWKS are fetched at startup and the
//     key set is cached and rotated automatically as the provider publishes new
//     keys. A private issuer whose own TLS certificate is not in the system
//     trust store is reachable via MCP_OAUTH_CA_ROOTS.
//
//   - Static JWKS file: MCP_OAUTH_JWKS_FILE points at a JWKS document on disk,
//     for air-gapped deployments or ones that sync keys by other means. The
//     file is hot-reloaded on mtime change (like a cert-manager-rotated
//     secret), so a key roll is picked up without a restart.
//
// Every failure mode here aborts startup loudly, matching the stance taken for
// the fence key and the fetch ACL: a typo in a credential-verification control
// must stop the server, not silently narrow it to static tokens only.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	oidc "github.com/coreos/go-oidc/v3/oidc"
	jose "github.com/go-jose/go-jose/v4"
)

// oauthMetadataPath is the RFC 9728 protected-resource metadata endpoint. When
// OAuth is enabled the relay serves it (unauthenticated — the document is
// public by design) and points 401 responses at it via the WWW-Authenticate
// resource_metadata parameter, so a spec-compliant MCP client can discover the
// issuer to authenticate against without out-of-band configuration.
const oauthMetadataPath = "/.well-known/oauth-protected-resource"

// defaultIdentityClaim is the token claim used as the audit identity when
// MCP_OAUTH_IDENTITY_CLAIM is unset. "sub" is the stable per-subject identifier
// every OIDC token carries.
const defaultIdentityClaim = "sub"

// asymmetricAlgs is the allow-list of JWS signing algorithms accepted for
// bearer JWTs. Asymmetric only, and set explicitly rather than left to a
// library default: it excludes the HMAC families so a token forged by signing
// with the issuer's *public* key as an HMAC secret (the RS256→HS256
// key-confusion attack) cannot verify, and it makes alg=none impossible by
// construction.
var asymmetricAlgs = []jose.SignatureAlgorithm{
	jose.RS256, jose.RS384, jose.RS512,
	jose.ES256, jose.ES384, jose.ES512,
	jose.PS256, jose.PS384, jose.PS512,
}

// supportedAlgStrings renders asymmetricAlgs as the []string form oidc.Config
// wants.
func supportedAlgStrings() []string {
	out := make([]string, len(asymmetricAlgs))
	for i, a := range asymmetricAlgs {
		out[i] = string(a)
	}
	return out
}

// oauthSettings is the compiled OAuth verifier. A nil *oauthSettings, or one
// whose verifier is nil, means OAuth is off and only the static token table
// applies — the enabled() guard is nil-safe so callers never check both.
type oauthSettings struct {
	verifier      *oidc.IDTokenVerifier
	issuer        string
	audience      string
	identityClaim string
	requiredScope string // empty means no scope requirement
	mode          string // "issuer" | "jwks-file", for the startup banner
	detail        string // banner detail: the issuer URL or "static keys (hot-reload)"
}

// enabled reports whether OAuth verification is configured.
func (o *oauthSettings) enabled() bool {
	return o != nil && o.verifier != nil
}

// describe renders the OAuth state for the startup banner.
func (o *oauthSettings) describe() string {
	if !o.enabled() {
		return "disabled (static tokens only)"
	}
	return o.mode + " (" + o.detail + ")"
}

// Verify validates a raw JWT (the token, without the "Bearer " prefix) and
// returns the identity to attribute the request to. It checks the signature
// against the current key set and the iss / aud / exp / nbf claims, then — when
// configured — the required scope, and finally extracts the identity claim.
// This is the only new work requireAuth performs for an OAuth caller.
func (o *oauthSettings) Verify(ctx context.Context, rawToken string) (string, error) {
	idt, err := o.verifier.Verify(ctx, rawToken)
	if err != nil {
		return "", err
	}
	var claims map[string]any
	if err := idt.Claims(&claims); err != nil {
		return "", fmt.Errorf("parse token claims: %w", err)
	}
	if o.requiredScope != "" && !claimHasScope(claims, o.requiredScope) {
		return "", fmt.Errorf("token is missing the required scope %q", o.requiredScope)
	}
	id := claimString(claims, o.identityClaim)
	if id == "" {
		// Fall back to the verified subject so a misconfigured identity claim
		// degrades to "sub" rather than to an empty (and thus unattributable)
		// identity.
		id = idt.Subject
	}
	if id == "" {
		return "", fmt.Errorf("token carries no %q claim to use as identity", o.identityClaim)
	}
	return id, nil
}

// metadataDocument returns the RFC 9728 protected-resource metadata as a JSON
// object. resource is this relay's audience (the identifier tokens must be
// minted for); authorization_servers names the issuer clients should obtain
// tokens from.
func (o *oauthSettings) metadataDocument() map[string]any {
	doc := map[string]any{
		"resource":                 o.audience,
		"authorization_servers":    []string{o.issuer},
		"bearer_methods_supported": []string{"header"},
	}
	if o.requiredScope != "" {
		doc["scopes_supported"] = []string{o.requiredScope}
	}
	return doc
}

// newOAuthSettings validates the MCP_OAUTH_* configuration and returns the
// compiled verifier, or (nil, nil) when OAuth is not configured. In issuer
// mode it performs OIDC discovery (a network call) so an unreachable or
// misconfigured issuer fails startup rather than the first authenticated
// request. Called from main(); a returned error aborts startup.
func newOAuthSettings(ctx context.Context, cfg Config) (*oauthSettings, error) {
	if cfg.OAuthIssuer == "" {
		// OAuth is off. Guard against a half-configuration: any other
		// MCP_OAUTH_* value without an issuer is a mistake that would
		// otherwise silently do nothing.
		if cfg.OAuthJWKSFile != "" || cfg.OAuthAudience != "" || cfg.OAuthCARoots != "" ||
			cfg.OAuthRequiredScope != "" || cfg.OAuthIdentityClaim != "" {
			return nil, fmt.Errorf("OAuth is half-configured: MCP_OAUTH_ISSUER is empty but other " +
				"MCP_OAUTH_* variables are set — set the issuer URL to enable OAuth, or unset the rest")
		}
		return nil, nil
	}
	if cfg.OAuthAudience == "" {
		return nil, fmt.Errorf("MCP_OAUTH_ISSUER is set but MCP_OAUTH_AUDIENCE is empty: name the " +
			"resource identifier tokens must carry in their aud claim (this relay), " +
			"e.g. \"https://relay.example.com\"")
	}
	if u, err := url.Parse(cfg.OAuthIssuer); err != nil || u.Scheme == "" || u.Host == "" {
		return nil, fmt.Errorf("MCP_OAUTH_ISSUER %q is not a valid absolute URL", cfg.OAuthIssuer)
	}

	identityClaim := cfg.OAuthIdentityClaim
	if identityClaim == "" {
		identityClaim = defaultIdentityClaim
	}
	s := &oauthSettings{
		issuer:        cfg.OAuthIssuer,
		audience:      cfg.OAuthAudience,
		identityClaim: identityClaim,
		requiredScope: cfg.OAuthRequiredScope,
	}
	oidcCfg := &oidc.Config{
		ClientID:             cfg.OAuthAudience,
		SupportedSigningAlgs: supportedAlgStrings(),
	}

	// Static JWKS file mode: keys come from disk, no network, hot-reloaded.
	if cfg.OAuthJWKSFile != "" {
		r := &jwksReloader{path: cfg.OAuthJWKSFile}
		if _, err := r.load(); err != nil {
			return nil, fmt.Errorf("MCP_OAUTH_JWKS_FILE %q: %w", cfg.OAuthJWKSFile, err)
		}
		s.verifier = oidc.NewVerifier(cfg.OAuthIssuer, r, oidcCfg)
		s.mode = "jwks-file"
		s.detail = "static keys (hot-reload)"
		return s, nil
	}

	// Issuer discovery mode: fetch the discovery document and JWKS from the
	// issuer, with the key set cached and rotated automatically thereafter.
	httpClient := &http.Client{Timeout: 30 * time.Second}
	if cfg.OAuthCARoots != "" {
		c, err := oauthHTTPClientWithRoots(cfg.OAuthCARoots)
		if err != nil {
			return nil, fmt.Errorf("MCP_OAUTH_CA_ROOTS %q: %w", cfg.OAuthCARoots, err)
		}
		httpClient = c
	}
	// The client attached here is retained by the provider for later JWKS
	// fetches, so a private-CA trust store scoped to OAuth stays in effect
	// without ever touching the fetch tool or the SearXNG client.
	provider, err := oidc.NewProvider(oidc.ClientContext(ctx, httpClient), cfg.OAuthIssuer)
	if err != nil {
		return nil, fmt.Errorf("OIDC discovery from MCP_OAUTH_ISSUER %q failed: %w", cfg.OAuthIssuer, err)
	}
	s.verifier = provider.Verifier(oidcCfg)
	s.mode = "issuer"
	s.detail = cfg.OAuthIssuer
	return s, nil
}

// claimString returns the named claim as a string, or "" when it is absent or
// not a string.
func claimString(claims map[string]any, name string) string {
	if v, ok := claims[name].(string); ok {
		return strings.TrimSpace(v)
	}
	return ""
}

// claimHasScope reports whether the token grants want. It accepts both shapes
// seen in the wild: a space-delimited "scope" string (RFC 8693 / OAuth) and a
// "scp" array (Entra and some others).
func claimHasScope(claims map[string]any, want string) bool {
	if s, ok := claims["scope"].(string); ok {
		for _, g := range strings.Fields(s) {
			if g == want {
				return true
			}
		}
	}
	if arr, ok := claims["scp"].([]any); ok {
		for _, g := range arr {
			if gs, ok := g.(string); ok && gs == want {
				return true
			}
		}
	}
	return false
}

// oauthHTTPClientWithRoots returns an HTTP client that trusts exactly the CA
// roots in pemPath, for talking to a private OIDC issuer (e.g. an internal
// Keycloak) whose own TLS certificate is not in the system trust store. The
// custom trust is scoped to OAuth discovery and JWKS fetching only; it does not
// affect the fetch tool or the SearXNG client.
func oauthHTTPClientWithRoots(pemPath string) (*http.Client, error) {
	pemBytes, err := os.ReadFile(pemPath)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pemBytes) {
		return nil, errors.New("no PEM certificates found in file")
	}
	return &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig:     &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
			TLSHandshakeTimeout: 10 * time.Second,
		},
	}, nil
}

// jwksReloader implements oidc.KeySet against a JWKS file, re-reading it when
// its mtime moves. It mirrors the manual-TLS cert reloader pattern: an in-place
// key rotation (an operator syncing a fresh JWKS) is picked up on the next
// verify without a restart, and a read that fails mid-write keeps serving the
// last good key set rather than failing live requests.
type jwksReloader struct {
	path string

	mu     sync.RWMutex
	cached *jose.JSONWebKeySet
	mod    time.Time
}

// VerifySignature satisfies oidc.KeySet: it parses the JWS, selects the key by
// kid (falling back to trying every key when the header carries none), and
// returns the verified payload.
func (r *jwksReloader) VerifySignature(_ context.Context, token string) ([]byte, error) {
	ks := r.currentIfFresh()
	if ks == nil {
		reloaded, err := r.load()
		if err != nil {
			if cached := r.current(); cached != nil {
				ks = cached // serve last good on a transient read failure
			} else {
				return nil, err
			}
		} else {
			ks = reloaded
		}
	}
	jws, err := jose.ParseSigned(token, asymmetricAlgs)
	if err != nil {
		return nil, err
	}
	var candidates []jose.JSONWebKey
	if len(jws.Signatures) > 0 {
		if kid := jws.Signatures[0].Header.KeyID; kid != "" {
			candidates = ks.Key(kid)
		}
	}
	if len(candidates) == 0 {
		candidates = ks.Keys
	}
	for i := range candidates {
		if payload, err := jws.Verify(&candidates[i]); err == nil {
			return payload, nil
		}
	}
	return nil, errors.New("no JWKS key verified the token signature")
}

// current returns the cached key set under a read lock, or nil.
func (r *jwksReloader) current() *jose.JSONWebKeySet {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.cached
}

// currentIfFresh returns the cached key set when the file still carries the
// modification time it was loaded from, and nil when a reload is due. A stat
// error falls back to the cached set so a transient FS hiccup does not drop a
// working key set.
func (r *jwksReloader) currentIfFresh() *jose.JSONWebKeySet {
	fi, err := os.Stat(r.path)
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.cached == nil {
		return nil
	}
	if err != nil || fi.ModTime().Equal(r.mod) {
		return r.cached
	}
	return nil
}

// load reads and parses the JWKS file and caches it with the file's
// modification time, so currentIfFresh can detect the next change.
func (r *jwksReloader) load() (*jose.JSONWebKeySet, error) {
	fi, err := os.Stat(r.path)
	if err != nil {
		return nil, err
	}
	raw, err := os.ReadFile(r.path)
	if err != nil {
		return nil, err
	}
	var ks jose.JSONWebKeySet
	if err := json.Unmarshal(raw, &ks); err != nil {
		return nil, fmt.Errorf("parse JWKS: %w", err)
	}
	if len(ks.Keys) == 0 {
		return nil, errors.New("JWKS file contains no keys")
	}
	r.mu.Lock()
	r.cached = &ks
	r.mod = fi.ModTime()
	r.mu.Unlock()
	return &ks, nil
}

// bearerToken extracts the token from an Authorization header value, returning
// "" when the header is absent or not a Bearer credential. The scheme match is
// case-insensitive per RFC 6750 / RFC 7235.
func bearerToken(header string) string {
	const prefix = "Bearer "
	if len(header) >= len(prefix) && strings.EqualFold(header[:len(prefix)], prefix) {
		return strings.TrimSpace(header[len(prefix):])
	}
	return ""
}

// resourceMetadataURL builds the absolute URL of the protected-resource
// metadata document for the WWW-Authenticate challenge, honouring the
// X-Forwarded-Proto / X-Forwarded-Host headers a terminating proxy sets so the
// advertised URL matches how the client actually reached the relay.
func resourceMetadataURL(r *http.Request) string {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	if p := r.Header.Get("X-Forwarded-Proto"); p != "" {
		scheme = strings.TrimSpace(strings.Split(p, ",")[0])
	}
	host := r.Host
	if h := r.Header.Get("X-Forwarded-Host"); h != "" {
		host = strings.TrimSpace(strings.Split(h, ",")[0])
	}
	return scheme + "://" + host + oauthMetadataPath
}

// handleOAuthMetadata serves the RFC 9728 protected-resource metadata. It is
// unauthenticated by design — the document only names the issuer and audience,
// which a client needs *before* it can obtain a token. Registered only when
// OAuth is enabled.
func (s *Server) handleOAuthMetadata(w http.ResponseWriter, r *http.Request) {
	if !s.config.OAuth.enabled() {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	_ = json.NewEncoder(w).Encode(s.config.OAuth.metadataDocument())
}
