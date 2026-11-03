// Package main: searxng_user_token.go — per-user OAuth tokens for SearXNG
// engines (RFC 8693 token exchange).
//
// By default the relay talks to SearXNG as itself: optional HTTP Basic auth
// (AUTH_USERNAME / AUTH_PASSWORD) and the per-process private-engine tokens
// (SEARXNG_TOKENS). Every caller shares that one upstream identity, so a
// SearXNG engine backed by a permission-aware system (a wiki, a ticket
// tracker, a document store) can only ever see a service account.
//
// With SEARXNG_USER_TOKEN_MODE=exchange the relay instead hands SearXNG a
// token for the *calling user*:
//
//  1. requireAuth verifies the caller's OAuth bearer token (aud = this relay)
//     and hands it to the MCP SDK as per-request TokenInfo, which also binds
//     the MCP session to that user.
//  2. On each searxng_web_search, the relay trades that token at the identity
//     provider (RFC 8693) for one issued to the search backend, for the same
//     user, and caches it until shortly before it expires.
//  3. The exchanged token travels to SearXNG in the X-Relay-User-Token header,
//     next to (never instead of) the relay's own Basic-auth credential.
//  4. A custom SearXNG engine reads that header and presents the token to its
//     backend as `Authorization: Bearer …`; the backend verifies it and
//     applies the user's own permissions.
//
// Security properties this file is responsible for, each pinned by a test in
// searxng_user_token_test.go:
//
//   - Exchange only, never passthrough. The caller's own token (aud = relay)
//     is never forwarded. A token leaked from SearXNG or the backend is only
//     good at the backend, and a caller's token is useless there.
//   - Only verified OAuth tokens are exchanged. Static MCP_AUTH_TOKEN* callers
//     have no user identity and get no header; nothing is ever substituted for
//     a missing user token, so the private engine sees no credential and
//     returns nothing (fail closed).
//   - A failed exchange fails the search. Falling back to a header-less search
//     would be safe but silent; the caller gets a generic error and the reason
//     goes to the log, never to the model.
//   - The token never follows a redirect. Go's http.Client forwards custom
//     headers to whatever host a redirect names; token-bearing searches use a
//     client that refuses every redirect.
//   - The token never crosses a network in clear text by accident. A plain
//     http:// SEARXNG_URL that is not loopback needs an explicit
//     SEARXNG_USER_TOKEN_ALLOW_PLAINTEXT=true, and the token endpoint must be
//     https:// (plain http only to loopback).
//   - Tokens never reach logs, metrics, errors or the model. The cache is keyed
//     by the SHA-256 of the caller's token, not by the token.
//   - Only searches carry it. URL fetches, engine discovery and health probes
//     never do.
//   - Fail loud on misconfiguration: half-configured settings, exchange
//     without OAuth verification, or a missing client secret stop startup.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// userTokenHeader is the request header that carries the exchanged user token
// from the relay to SearXNG. Fixed rather than configurable: the SearXNG engine
// that reads it ships with the relay (deploy/searxng-engine), and a fixed name
// is one less setting to get wrong. It is deliberately not Authorization, which
// already carries the relay's own Basic-auth credential to SearXNG.
const userTokenHeader = "X-Relay-User-Token"

const (
	userTokenModeOff      = "off"
	userTokenModeExchange = "exchange"

	grantTokenExchange   = "urn:ietf:params:oauth:grant-type:token-exchange"
	tokenTypeAccessToken = "urn:ietf:params:oauth:token-type:access_token"

	// userTokenEarlyRenewal treats an exchanged token as expired this long
	// before it is, so it never expires between the cache and the backend.
	userTokenEarlyRenewal = 30 * time.Second
	// userTokenDefaultLifetime is assumed when the provider reports no
	// expires_in. Short on purpose: an unknown lifetime is not a long one.
	userTokenDefaultLifetime = 60 * time.Second
	// userTokenMaxLifetime caps how long an exchanged token is reused,
	// whatever the provider says, so a revoked user stops reaching the
	// backend within this window even if the provider issues long tokens.
	userTokenMaxLifetime = 10 * time.Minute
	// userTokenCacheEntries bounds the exchanged-token cache.
	userTokenCacheEntries = 1024
	// maxUserTokenBytes caps an exchanged token. Real access tokens are a few
	// KB at most; anything larger is a provider bug or an attack on SearXNG's
	// header limits.
	maxUserTokenBytes = 8 << 10
	// tokenEndpointResponseLimit caps how much of a token-endpoint response is
	// read.
	tokenEndpointResponseLimit = 64 << 10
)

// userTokenOutcomes labels mcp_searxng_user_token_total. Order is the index
// into Metrics.UserToken.
var userTokenOutcomes = [...]string{"exchanged", "cached", "no_user_token", "failed"}

const (
	userTokenExchanged = iota
	userTokenCached
	userTokenNoUser
	userTokenFailed
)

// errNoUserToken is returned by userTokenForSearch when the caller holds no
// verified OAuth token (a static-token caller, or stdio). It is not a failure:
// the search runs without the header.
var errNoUserToken = errors.New("caller has no verified OAuth token")

// errUserTokenUnavailable is what the caller (and so the model) sees when the
// exchange fails. The real reason is logged; the provider's error text can
// name clients and audiences, which the model has no use for.
var errUserTokenUnavailable = errors.New("search unavailable: could not obtain a user token for the search backend; the reason is in the relay log")

// ── getting the verified token to the tool handler ────────────────────────────
//
// The obvious route — put the token on the HTTP request's context — is wrong
// in stateful mode. The MCP SDK runs a session's tool calls under a context
// derived from the request that *created* the session, so a handler would see
// the first token of the session forever: a refreshed token would be ignored,
// the original would expire and every later search would fail, and anyone who
// learned the session ID could search under the creator's identity.
//
// What the SDK does carry per HTTP request is RequestExtra.TokenInfo, set by
// its auth.RequireBearerToken middleware. So once requireAuth has verified an
// OAuth token, withSDKTokenInfo hands the SDK a TokenInfo holding the identity,
// the expiry and the raw token. That buys two things:
//
//   - the tool handler reads the token of the request it is serving
//     (oauthTokenFromRequest), never one remembered from the session; and
//   - the SDK records TokenInfo.UserID when a session is created and answers
//     403 "session user mismatch" to any later request on that session from
//     another user, or from a caller with no OAuth identity at all.

// sdkTokenExtraKey is the TokenInfo.Extra key holding the raw verified token.
const sdkTokenExtraKey = "mcp-searxng-relay/verified-oauth-token"

// withSDKTokenInfo wraps next in the SDK's bearer middleware with a verifier
// that returns what requireAuth has already verified. The SDK re-reads the
// same Authorization header and checks the expiry once more; it does not
// verify the signature again, which requireAuth has just done.
func withSDKTokenInfo(identity string, expiry time.Time, token string, next http.Handler) http.Handler {
	info := &auth.TokenInfo{
		UserID:     identity,
		Expiration: expiry,
		Extra:      map[string]any{sdkTokenExtraKey: token},
	}
	verified := func(context.Context, string, *http.Request) (*auth.TokenInfo, error) { return info, nil }
	return auth.RequireBearerToken(verified, nil)(next)
}

// oauthTokenFromTokenInfo returns the verified token withSDKTokenInfo stored,
// or "" for nil or a TokenInfo without one.
func oauthTokenFromTokenInfo(ti *auth.TokenInfo) string {
	if ti == nil {
		return ""
	}
	tok, _ := ti.Extra[sdkTokenExtraKey].(string)
	return tok
}

// oauthTokenFromRequest returns the verified OAuth token of the HTTP request
// carrying this tool call, or "" (static-token caller, stdio, in-memory
// transport).
func oauthTokenFromRequest(req *mcp.CallToolRequest) string {
	if req == nil || req.Extra == nil {
		return ""
	}
	return oauthTokenFromTokenInfo(req.Extra.TokenInfo)
}

type verifiedOAuthTokenCtxKey struct{}

// withVerifiedOAuthToken binds the token of the current tool call into ctx for
// the search pipeline. toolSearch always calls it, with "" when there is no
// token, so nothing set on a longer-lived context can show through.
func withVerifiedOAuthToken(ctx context.Context, raw string) context.Context {
	return context.WithValue(ctx, verifiedOAuthTokenCtxKey{}, raw)
}

// verifiedOAuthTokenFromContext returns the token bound by toolSearch, or "".
func verifiedOAuthTokenFromContext(ctx context.Context) string {
	if v, ok := ctx.Value(verifiedOAuthTokenCtxKey{}).(string); ok {
		return v
	}
	return ""
}

// ── configuration ─────────────────────────────────────────────────────────────

// userTokenExchanger trades verified caller tokens for search-backend tokens.
// A nil *userTokenExchanger means the feature is off; every method is nil-safe
// so call sites need no separate guard.
type userTokenExchanger struct {
	tokenURL     string
	clientID     string
	clientSecret string
	audience     string // optional: sent as the RFC 8693 audience parameter
	client       *http.Client

	mu    sync.Mutex
	cache *lru.Cache[[32]byte, cachedUserToken]
	now   func() time.Time // injectable for tests
}

type cachedUserToken struct {
	token   string
	expires time.Time
}

// enabled reports whether user-token exchange is configured.
func (x *userTokenExchanger) enabled() bool { return x != nil }

// describe renders the feature state for the startup banner. Never prints the
// secret.
func (x *userTokenExchanger) describe() string {
	if !x.enabled() {
		return userTokenModeOff
	}
	d := "exchange (client " + x.clientID
	if x.audience != "" {
		d += ", audience " + x.audience
	}
	return d + ", header " + userTokenHeader + ")"
}

// newUserTokenExchanger validates the SEARXNG_USER_TOKEN_* settings and
// returns the compiled exchanger, or (nil, nil) when the feature is off.
// oauthOn is whether the relay verifies OAuth bearer tokens: without that there
// is no verified user token to exchange, so exchange mode refuses to start.
// Called from main(); a returned error aborts startup.
func newUserTokenExchanger(cfg Config, oauthOn bool, httpClient *http.Client) (*userTokenExchanger, error) {
	mode := strings.ToLower(strings.TrimSpace(cfg.UserTokenMode))
	anySet := cfg.UserTokenURL != "" || cfg.UserTokenClientID != "" || cfg.UserTokenClientSecret != "" ||
		cfg.UserTokenClientSecretFile != "" || cfg.UserTokenAudience != "" || cfg.UserTokenAllowPlaintext

	switch mode {
	case "", userTokenModeOff:
		if anySet {
			return nil, errors.New("SEARXNG_USER_TOKEN_* is set but SEARXNG_USER_TOKEN_MODE is off: " +
				"set SEARXNG_USER_TOKEN_MODE=exchange to use it, or unset the rest")
		}
		return nil, nil
	case userTokenModeExchange:
	case "passthrough":
		return nil, errors.New("SEARXNG_USER_TOKEN_MODE=passthrough is not supported: forwarding the caller's " +
			"own token would make it valid at the search backend too; use exchange")
	default:
		return nil, fmt.Errorf("SEARXNG_USER_TOKEN_MODE %q is not one of off, exchange", cfg.UserTokenMode)
	}

	if !oauthOn {
		return nil, errors.New("SEARXNG_USER_TOKEN_MODE=exchange needs OAuth verification (MCP_OAUTH_ISSUER and " +
			"MCP_OAUTH_AUDIENCE): only a verified OAuth token identifies a user to exchange")
	}

	secret := cfg.UserTokenClientSecret
	if secret != "" && cfg.UserTokenClientSecretFile != "" {
		return nil, errors.New("set SEARXNG_USER_TOKEN_CLIENT_SECRET or SEARXNG_USER_TOKEN_CLIENT_SECRET_FILE, not both")
	}
	if cfg.UserTokenClientSecretFile != "" {
		b, err := os.ReadFile(cfg.UserTokenClientSecretFile)
		if err != nil {
			return nil, fmt.Errorf("read SEARXNG_USER_TOKEN_CLIENT_SECRET_FILE: %w", err)
		}
		secret = strings.TrimSpace(string(b))
	}

	var missing []string
	if cfg.UserTokenURL == "" {
		missing = append(missing, "SEARXNG_USER_TOKEN_URL")
	}
	if cfg.UserTokenClientID == "" {
		missing = append(missing, "SEARXNG_USER_TOKEN_CLIENT_ID")
	}
	if secret == "" {
		missing = append(missing, "SEARXNG_USER_TOKEN_CLIENT_SECRET (or _FILE)")
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("SEARXNG_USER_TOKEN_MODE=exchange needs %s", strings.Join(missing, ", "))
	}

	if u, err := url.Parse(cfg.UserTokenURL); err != nil || u.Host == "" ||
		(u.Scheme != "https" && !(u.Scheme == "http" && isLoopbackHost(u.Hostname()))) {
		return nil, fmt.Errorf("SEARXNG_USER_TOKEN_URL %q must be an https:// URL (plain http only to this "+
			"machine): it carries the relay's client secret and users' tokens", cfg.UserTokenURL)
	}

	// The exchanged token rides to SearXNG in a header. Over plain http to
	// another machine anyone on the path can read and replay it, so that
	// needs an explicit opt-in (typically: in-cluster traffic locked down by
	// a NetworkPolicy).
	su, err := url.Parse(cfg.SearxngURL)
	if err != nil || su.Host == "" {
		return nil, fmt.Errorf("SEARXNG_URL %q is not a valid absolute URL", cfg.SearxngURL)
	}
	if su.Scheme != "https" && !isLoopbackHost(su.Hostname()) && !cfg.UserTokenAllowPlaintext {
		return nil, fmt.Errorf("SEARXNG_URL %q is plain http to another host, which would send users' tokens "+
			"in clear text: use https, or set SEARXNG_USER_TOKEN_ALLOW_PLAINTEXT=true if the network path "+
			"is private and locked down (e.g. in-cluster behind a NetworkPolicy)", cfg.SearxngURL)
	}

	if httpClient == nil {
		httpClient = &http.Client{Timeout: 15 * time.Second}
	}
	// The token endpoint must answer directly. A redirect would carry the
	// relay's client secret and the user's token to wherever it points.
	c := *httpClient
	c.CheckRedirect = refuseRedirect
	cache, err := lru.New[[32]byte, cachedUserToken](userTokenCacheEntries)
	if err != nil {
		return nil, err
	}
	return &userTokenExchanger{
		tokenURL:     cfg.UserTokenURL,
		clientID:     cfg.UserTokenClientID,
		clientSecret: secret,
		audience:     cfg.UserTokenAudience,
		client:       &c,
		cache:        cache,
		now:          time.Now,
	}, nil
}

// refuseRedirect is a CheckRedirect that never follows a redirect. The response
// carrying the redirect is returned as the error's cause, so callers see a
// non-200 and fail.
func refuseRedirect(*http.Request, []*http.Request) error {
	return errors.New("redirect refused: this request carries a user token")
}

// isLoopbackHost reports whether host is localhost or a loopback IP literal.
func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// ── exchange ──────────────────────────────────────────────────────────────────

// Exchange returns a search-backend token for the user whose verified token is
// subject, from the cache when a fresh one is there. cached reports which.
func (x *userTokenExchanger) Exchange(ctx context.Context, subject string) (token string, cached bool, err error) {
	key := sha256.Sum256([]byte(subject))
	now := x.now()

	x.mu.Lock()
	if c, ok := x.cache.Get(key); ok {
		if now.Before(c.expires) {
			x.mu.Unlock()
			return c.token, true, nil
		}
		x.cache.Remove(key)
	}
	x.mu.Unlock()

	form := url.Values{
		"grant_type":           {grantTokenExchange},
		"subject_token":        {subject},
		"subject_token_type":   {tokenTypeAccessToken},
		"requested_token_type": {tokenTypeAccessToken},
	}
	if x.audience != "" {
		form.Set("audience", x.audience)
	}
	tok, err := x.request(ctx, form, now)
	if err != nil {
		return "", false, err
	}

	x.mu.Lock()
	x.cache.Add(key, tok)
	x.mu.Unlock()
	return tok.token, false, nil
}

// request posts form to the token endpoint as a confidential client (HTTP
// Basic, which Keycloak and authentik both accept). Error values carry the
// provider's error code and description, never a token.
func (x *userTokenExchanger) request(ctx context.Context, form url.Values, started time.Time) (cachedUserToken, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, x.tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return cachedUserToken{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	// RFC 6749 §2.3.1: client_id and secret are form-encoded before Basic.
	req.SetBasicAuth(url.QueryEscape(x.clientID), url.QueryEscape(x.clientSecret))

	resp, err := x.client.Do(req)
	if err != nil {
		// *url.Error names the token URL and the cause; neither is secret.
		return cachedUserToken{}, fmt.Errorf("token endpoint: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, tokenEndpointResponseLimit))
	if err != nil {
		return cachedUserToken{}, fmt.Errorf("token endpoint: %w", err)
	}

	var out struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		ExpiresIn   int64  `json:"expires_in"`
		Error       string `json:"error"`
		Description string `json:"error_description"`
	}
	_ = json.Unmarshal(body, &out)
	if resp.StatusCode != http.StatusOK {
		if out.Error != "" {
			return cachedUserToken{}, fmt.Errorf("token endpoint returned %s: %s %s",
				resp.Status, logSafe(out.Error, 64), logSafe(out.Description, 256))
		}
		return cachedUserToken{}, fmt.Errorf("token endpoint returned %s", resp.Status)
	}
	if out.AccessToken == "" {
		return cachedUserToken{}, errors.New("token endpoint returned no access_token")
	}
	if out.TokenType != "" && !strings.EqualFold(out.TokenType, "bearer") {
		return cachedUserToken{}, fmt.Errorf("token endpoint returned token_type %q, want Bearer", logSafe(out.TokenType, 32))
	}
	if err := validHeaderToken(out.AccessToken); err != nil {
		return cachedUserToken{}, fmt.Errorf("token endpoint returned an unusable access_token: %w", err)
	}

	life := userTokenDefaultLifetime
	if out.ExpiresIn > 0 {
		life = time.Duration(out.ExpiresIn) * time.Second
	}
	if life > userTokenMaxLifetime {
		life = userTokenMaxLifetime
	}
	expires := started.Add(life - userTokenEarlyRenewal)
	if life <= userTokenEarlyRenewal {
		expires = started.Add(life / 2)
	}
	return cachedUserToken{token: out.AccessToken, expires: expires}, nil
}

// validHeaderToken checks that tok can be sent as a header value unchanged:
// bounded, and only visible ASCII (RFC 6750 b64token is a subset). A token with
// a CR or LF would be a header-injection attempt; Go's transport rejects those
// too, but checking here turns it into a clear exchange failure.
func validHeaderToken(tok string) error {
	if len(tok) > maxUserTokenBytes {
		return fmt.Errorf("token is %d bytes, more than the %d allowed", len(tok), maxUserTokenBytes)
	}
	for i := 0; i < len(tok); i++ {
		if c := tok[i]; c <= 0x20 || c >= 0x7f {
			return errors.New("token contains a character that is not visible ASCII")
		}
	}
	return nil
}

// logSafe trims provider-supplied text for a log line: control characters
// become spaces and the result is capped at max bytes.
func logSafe(s string, max int) string {
	b := []byte(s)
	if len(b) > max {
		b = b[:max]
	}
	for i, c := range b {
		if c < 0x20 || c == 0x7f {
			b[i] = ' '
		}
	}
	return string(b)
}

// ── use on the search path ────────────────────────────────────────────────────

// userTokenForSearch returns the backend token to send with this search.
//
//   - feature off: "", nil — send nothing.
//   - caller has no verified OAuth token: "", errNoUserToken — send nothing;
//     the private engine sees no credential and returns nothing.
//   - exchange failed: "", errUserTokenUnavailable — the search must fail.
func (s *Server) userTokenForSearch(ctx context.Context) (string, error) {
	x := s.config.UserTokenExchange
	if !x.enabled() {
		return "", nil
	}
	subject := verifiedOAuthTokenFromContext(ctx)
	if subject == "" {
		s.metrics.UserToken[userTokenNoUser].Add(1)
		callerLogger(ctx).Debug("search sent without a user token: caller is not an OAuth user")
		return "", errNoUserToken
	}
	tok, cached, err := x.Exchange(ctx, subject)
	if err != nil {
		s.metrics.UserToken[userTokenFailed].Add(1)
		callerLogger(ctx).Warn("user token exchange failed; search refused", "error", err.Error())
		return "", errUserTokenUnavailable
	}
	if cached {
		s.metrics.UserToken[userTokenCached].Add(1)
	} else {
		s.metrics.UserToken[userTokenExchanged].Add(1)
	}
	return tok, nil
}
