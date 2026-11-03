package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// These tests pin the security contract of searxng_user_token.go. The ones
// that matter most are the negatives: the caller's own token never reaches
// SearXNG, a static-token caller never gets a user token, a failed exchange
// never turns into a search under no identity or someone else's, the token
// never follows a redirect, and it never reaches a log line.

// ── fixtures ──────────────────────────────────────────────────────────────────

const (
	testUserTokenClientID = "relay-client"
	testUserTokenSecret   = "relay-secret-value"
	testUserTokenAudience = "search-backend"
)

// fakeIDP is a token endpoint implementing just enough of RFC 8693. The token
// it issues is derived from the subject token, so a test can tell which caller
// a header belongs to without the subject token ever being sent onward.
type fakeIDP struct {
	srv       *httptest.Server
	calls     atomic.Int64
	mu        sync.Mutex
	lastForm  map[string]string
	lastBasic [2]string
	// respond, when set, replaces the default success response.
	respond func(w http.ResponseWriter, r *http.Request)
}

func backendTokenFor(subject string) string {
	h := sha256.Sum256([]byte(subject))
	return "backend." + hex.EncodeToString(h[:8])
}

func newFakeIDP(t *testing.T) *fakeIDP {
	t.Helper()
	f := &fakeIDP{}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.calls.Add(1)
		_ = r.ParseForm()
		u, p, _ := r.BasicAuth()
		f.mu.Lock()
		f.lastForm = map[string]string{}
		for k := range r.PostForm {
			f.lastForm[k] = r.PostForm.Get(k)
		}
		f.lastBasic = [2]string{u, p}
		f.mu.Unlock()
		if f.respond != nil {
			f.respond(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"` + backendTokenFor(r.PostForm.Get("subject_token")) +
			`","token_type":"Bearer","expires_in":300,"issued_token_type":"` + tokenTypeAccessToken + `"}`))
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeIDP) form() map[string]string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.lastForm
}

// exchangeConfig is a valid exchange-mode Config against idp.
func exchangeConfig(idp *fakeIDP, searxngURL string) Config {
	return Config{
		SearxngURL:            searxngURL,
		UserTokenMode:         "exchange",
		UserTokenURL:          idp.srv.URL + "/token",
		UserTokenClientID:     testUserTokenClientID,
		UserTokenClientSecret: testUserTokenSecret,
		UserTokenAudience:     testUserTokenAudience,
	}
}

func mustExchanger(t *testing.T, cfg Config) *userTokenExchanger {
	t.Helper()
	x, err := newUserTokenExchanger(cfg, true, nil)
	if err != nil {
		t.Fatalf("newUserTokenExchanger: %v", err)
	}
	if !x.enabled() {
		t.Fatal("expected exchange to be enabled")
	}
	return x
}

// fakeSearxng records the user-token header of every search it serves.
type fakeSearxng struct {
	srv     *httptest.Server
	mu      sync.Mutex
	headers []string // X-Relay-User-Token per request ("" when absent)
	calls   atomic.Int64
	handler func(w http.ResponseWriter, r *http.Request) // optional override
}

func newFakeSearxng(t *testing.T) *fakeSearxng {
	t.Helper()
	f := &fakeSearxng{}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.calls.Add(1)
		f.mu.Lock()
		f.headers = append(f.headers, r.Header.Get(userTokenHeader))
		f.mu.Unlock()
		if f.handler != nil {
			f.handler(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"results":[{"title":"t","url":"https://example.com/a","content":"c","engines":["private"]}]}`))
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeSearxng) seen() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.headers...)
}

// userTokenServer builds a relay with OAuth (static JWKS) and, when
// exchangeOn, user-token exchange against idp, plus a static token for
// "static-bot". It returns the server, the MCP root admission chain wrapping a
// handler that runs one search, and a minter for OAuth tokens.
func userTokenServer(t *testing.T, idp *fakeIDP, sx *fakeSearxng, exchangeOn bool) (*Server, func(sub string) string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "jwks.json")
	priv, pub := oauthTestKey(t, "k1")
	oauthWriteJWKS(t, path, pub)

	cfg := Config{
		SearxngURL:      sx.srv.URL,
		CacheMaxEntries: 1,
		OAuth:           fileModeSettings(t, path, nil),
		AuthTokens:      map[tokenDigest]string{sha256.Sum256([]byte("Bearer static-secret-0123456789abcdef")): "static-bot"},
	}
	if exchangeOn {
		cfg.UserTokenExchange = mustExchanger(t, exchangeConfig(idp, sx.srv.URL))
	}
	s := NewServer(cfg)
	var n atomic.Int64
	mint := func(sub string) string {
		c := oauthBaseClaims()
		c["sub"] = sub
		// A unique jti per token, so two tokens for one user differ the
		// way a refreshed token does.
		c["jti"] = sub + "-" + strconv.FormatInt(n.Add(1), 10)
		return oauthSignToken(t, priv, "k1", c)
	}
	return s, mint
}

// searchVia runs one search behind requireAuth with the given Authorization
// header and returns the search error.
func searchVia(t *testing.T, s *Server, authz string) error {
	t.Helper()
	var searchErr error
	h := s.requireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// What toolSearch does with req.Extra.TokenInfo.
		ctx := withVerifiedOAuthToken(r.Context(), oauthTokenFromTokenInfo(auth.TokenInfoFromContext(r.Context())))
		_, searchErr = s.search(ctx, "q", 1, "", "all", "", 0, "")
	}))
	r := httptest.NewRequest(http.MethodPost, "/", nil)
	r.Header.Set("Authorization", authz)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("requireAuth rejected the request: %d", w.Code)
	}
	return searchErr
}

// ── configuration ─────────────────────────────────────────────────────────────

func TestNewUserTokenExchanger_OffByDefault(t *testing.T) {
	x, err := newUserTokenExchanger(Config{SearxngURL: "http://searxng:8080"}, true, nil)
	if err != nil || x != nil {
		t.Fatalf("got (%v, %v), want (nil, nil)", x, err)
	}
	if x.enabled() {
		t.Error("nil exchanger must report disabled")
	}
}

func TestNewUserTokenExchanger_RejectsBadConfig(t *testing.T) {
	idp := newFakeIDP(t)
	valid := exchangeConfig(idp, "https://searxng.example")
	secretFile := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(secretFile, []byte("s3cret\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name    string
		mutate  func(c *Config)
		oauthOn bool
		want    string
	}{
		{"settings without mode", func(c *Config) { c.UserTokenMode = "" }, true, "SEARXNG_USER_TOKEN_MODE is off"},
		{"plaintext flag without mode", func(c *Config) { *c = Config{SearxngURL: c.SearxngURL, UserTokenAllowPlaintext: true} }, true, "is off"},
		{"passthrough refused", func(c *Config) { c.UserTokenMode = "passthrough" }, true, "not supported"},
		{"unknown mode", func(c *Config) { c.UserTokenMode = "exchnage" }, true, "not one of"},
		{"no oauth verification", func(c *Config) {}, false, "needs OAuth verification"},
		{"missing token url", func(c *Config) { c.UserTokenURL = "" }, true, "SEARXNG_USER_TOKEN_URL"},
		{"missing client id", func(c *Config) { c.UserTokenClientID = "" }, true, "SEARXNG_USER_TOKEN_CLIENT_ID"},
		{"missing secret", func(c *Config) { c.UserTokenClientSecret = "" }, true, "CLIENT_SECRET"},
		{"both secrets", func(c *Config) { c.UserTokenClientSecretFile = secretFile }, true, "not both"},
		{"unreadable secret file", func(c *Config) {
			c.UserTokenClientSecret = ""
			c.UserTokenClientSecretFile = filepath.Join(t.TempDir(), "missing")
		}, true, "SECRET_FILE"},
		{"http token url to another host", func(c *Config) { c.UserTokenURL = "http://idp.example/token" }, true, "must be an https://"},
		{"relative token url", func(c *Config) { c.UserTokenURL = "/token" }, true, "must be an https://"},
		{"plaintext searxng url", func(c *Config) { c.SearxngURL = "http://searxng:8080" }, true, "clear text"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := valid
			tc.mutate(&c)
			x, err := newUserTokenExchanger(c, tc.oauthOn, nil)
			if err == nil {
				t.Fatalf("accepted bad config (exchanger %v)", x)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not mention %q", err, tc.want)
			}
			if strings.Contains(err.Error(), testUserTokenSecret) {
				t.Errorf("error leaks the client secret: %q", err)
			}
		})
	}
}

func TestNewUserTokenExchanger_AcceptsGoodConfig(t *testing.T) {
	idp := newFakeIDP(t)
	secretFile := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(secretFile, []byte("from-file\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name   string
		mutate func(c *Config)
	}{
		{"https searxng", func(*Config) {}},
		{"loopback http searxng", func(c *Config) { c.SearxngURL = "http://127.0.0.1:8888" }},
		{"plaintext opted in", func(c *Config) { c.SearxngURL = "http://searxng:8080"; c.UserTokenAllowPlaintext = true }},
		{"secret from file", func(c *Config) { c.UserTokenClientSecret = ""; c.UserTokenClientSecretFile = secretFile }},
		{"mode is case-insensitive", func(c *Config) { c.UserTokenMode = "Exchange" }},
		{"no audience", func(c *Config) { c.UserTokenAudience = "" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := exchangeConfig(idp, "https://searxng.example")
			tc.mutate(&c)
			x := mustExchanger(t, c)
			if strings.Contains(x.describe(), x.clientSecret) {
				t.Errorf("banner leaks the client secret: %q", x.describe())
			}
		})
	}
}

// ── the exchange itself ───────────────────────────────────────────────────────

func TestExchange_SendsRFC8693Request(t *testing.T) {
	idp := newFakeIDP(t)
	x := mustExchanger(t, exchangeConfig(idp, "https://searxng.example"))

	tok, cached, err := x.Exchange(context.Background(), "caller-token")
	if err != nil {
		t.Fatal(err)
	}
	if cached {
		t.Error("first exchange reported as cached")
	}
	if tok != backendTokenFor("caller-token") {
		t.Errorf("token = %q, want the exchanged one", tok)
	}
	f := idp.form()
	want := map[string]string{
		"grant_type":           grantTokenExchange,
		"subject_token":        "caller-token",
		"subject_token_type":   tokenTypeAccessToken,
		"requested_token_type": tokenTypeAccessToken,
		"audience":             testUserTokenAudience,
	}
	for k, v := range want {
		if f[k] != v {
			t.Errorf("form %s = %q, want %q", k, f[k], v)
		}
	}
	if _, ok := f["client_secret"]; ok {
		t.Error("client secret sent in the form body; it belongs in Basic auth")
	}
	if idp.lastBasic != [2]string{testUserTokenClientID, testUserTokenSecret} {
		t.Errorf("basic auth = %v", idp.lastBasic)
	}
}

func TestExchange_CachesPerCallerAndRenews(t *testing.T) {
	idp := newFakeIDP(t)
	x := mustExchanger(t, exchangeConfig(idp, "https://searxng.example"))
	now := time.Now()
	x.now = func() time.Time { return now }
	ctx := context.Background()

	a1, _, _ := x.Exchange(ctx, "alice")
	a2, cached, _ := x.Exchange(ctx, "alice")
	if !cached || a1 != a2 || idp.calls.Load() != 1 {
		t.Fatalf("second exchange for the same token: cached=%v calls=%d", cached, idp.calls.Load())
	}
	b, _, _ := x.Exchange(ctx, "bob")
	if b == a1 || idp.calls.Load() != 2 {
		t.Fatalf("a different caller must never get another caller's token (calls=%d)", idp.calls.Load())
	}

	// expires_in=300 → reused until 30s before expiry, then exchanged again.
	now = now.Add(269 * time.Second)
	if _, cached, _ := x.Exchange(ctx, "alice"); !cached {
		t.Error("token renewed too early")
	}
	now = now.Add(2 * time.Second)
	if _, cached, _ := x.Exchange(ctx, "alice"); cached {
		t.Error("token used within the early-renewal window")
	}
}

func TestExchange_CapsLifetime(t *testing.T) {
	idp := newFakeIDP(t)
	idp.respond = func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"access_token":"long-lived","token_type":"Bearer","expires_in":86400}`))
	}
	x := mustExchanger(t, exchangeConfig(idp, "https://searxng.example"))
	now := time.Now()
	x.now = func() time.Time { return now }
	_, _, _ = x.Exchange(context.Background(), "alice")
	now = now.Add(userTokenMaxLifetime)
	if _, cached, _ := x.Exchange(context.Background(), "alice"); cached {
		t.Error("a day-long token was reused past the lifetime cap")
	}
}

func TestExchange_RejectsBadResponses(t *testing.T) {
	cases := []struct {
		name   string
		status int
		body   string
		want   string
	}{
		{"provider error", 400, `{"error":"invalid_grant","error_description":"subject token not trusted"}`, "invalid_grant"},
		{"bare 500", 500, `oops`, "500"},
		{"no token", 200, `{"token_type":"Bearer"}`, "no access_token"},
		{"wrong token type", 200, `{"access_token":"x","token_type":"N_A"}`, "token_type"},
		{"header injection", 200, `{"access_token":"abc\r\nX-Evil: 1","token_type":"Bearer"}`, "not visible ASCII"},
		{"space in token", 200, `{"access_token":"abc def","token_type":"Bearer"}`, "not visible ASCII"},
		{"oversized token", 200, `{"access_token":"` + strings.Repeat("a", maxUserTokenBytes+1) + `"}`, "allowed"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			idp := newFakeIDP(t)
			idp.respond = func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}
			x := mustExchanger(t, exchangeConfig(idp, "https://searxng.example"))
			_, _, err := x.Exchange(context.Background(), "subject-token-value")
			if err == nil {
				t.Fatal("accepted a bad token-endpoint response")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not mention %q", err, tc.want)
			}
			if strings.Contains(err.Error(), "subject-token-value") {
				t.Errorf("error leaks the subject token: %q", err)
			}
		})
	}
}

func TestExchange_RefusesRedirectFromTokenEndpoint(t *testing.T) {
	var elsewhere atomic.Int64
	other := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { elsewhere.Add(1) }))
	t.Cleanup(other.Close)
	idp := newFakeIDP(t)
	idp.respond = func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL+"/steal", http.StatusTemporaryRedirect)
	}
	x := mustExchanger(t, exchangeConfig(idp, "https://searxng.example"))
	if _, _, err := x.Exchange(context.Background(), "alice"); err == nil {
		t.Fatal("exchange followed a redirect")
	}
	if elsewhere.Load() != 0 {
		t.Error("the subject token and client secret were re-sent to the redirect target")
	}
}

// ── the search path ───────────────────────────────────────────────────────────

func TestSearch_OAuthCallerSendsExchangedTokenNotOwn(t *testing.T) {
	idp, sx := newFakeIDP(t), newFakeSearxng(t)
	s, mint := userTokenServer(t, idp, sx, true)
	alice := mint("alice")

	if err := searchVia(t, s, "Bearer "+alice); err != nil {
		t.Fatalf("search: %v", err)
	}
	got := sx.seen()
	if len(got) != 1 || got[0] != backendTokenFor(alice) {
		t.Fatalf("SearXNG saw %q, want the exchanged token", got)
	}
	if got[0] == alice || strings.Contains(got[0], alice) {
		t.Fatal("the caller's own token reached SearXNG")
	}
	if n := s.metrics.UserToken[userTokenExchanged].Load(); n != 1 {
		t.Errorf("exchanged counter = %d", n)
	}

	// Second search reuses the cached token.
	if err := searchVia(t, s, "Bearer "+alice); err != nil {
		t.Fatal(err)
	}
	if idp.calls.Load() != 1 || s.metrics.UserToken[userTokenCached].Load() != 1 {
		t.Errorf("second search: idp calls=%d cached=%d", idp.calls.Load(), s.metrics.UserToken[userTokenCached].Load())
	}
}

func TestSearch_StaticCallerGetsNoUserToken(t *testing.T) {
	idp, sx := newFakeIDP(t), newFakeSearxng(t)
	s, _ := userTokenServer(t, idp, sx, true)

	if err := searchVia(t, s, "Bearer static-secret-0123456789abcdef"); err != nil {
		t.Fatalf("static caller's search must still run: %v", err)
	}
	if got := sx.seen(); len(got) != 1 || got[0] != "" {
		t.Fatalf("static caller sent %q to SearXNG, want no user token", got)
	}
	if idp.calls.Load() != 0 {
		t.Error("a static token was sent to the identity provider")
	}
	if s.metrics.UserToken[userTokenNoUser].Load() != 1 {
		t.Error("no_user_token not counted")
	}
}

func TestSearch_FailedExchangeRefusesSearch(t *testing.T) {
	idp, sx := newFakeIDP(t), newFakeSearxng(t)
	idp.respond = func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"unauthorized_client","error_description":"client relay-client may not exchange"}`))
	}
	s, mint := userTokenServer(t, idp, sx, true)

	err := searchVia(t, s, "Bearer "+mint("alice"))
	if !errors.Is(err, errUserTokenUnavailable) {
		t.Fatalf("err = %v, want errUserTokenUnavailable", err)
	}
	if sx.calls.Load() != 0 {
		t.Fatal("search ran after the exchange failed")
	}
	if strings.Contains(err.Error(), "unauthorized_client") {
		t.Error("the provider's error text reached the caller")
	}
	if s.metrics.UserToken[userTokenFailed].Load() != 1 {
		t.Error("failed not counted")
	}
}

func TestSearch_UserTokenNeverFollowsRedirect(t *testing.T) {
	var leaked atomic.Value
	leaked.Store("")
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		leaked.Store(r.Header.Get(userTokenHeader))
		_, _ = w.Write([]byte(`{"results":[]}`))
	}))
	t.Cleanup(other.Close)

	idp, sx := newFakeIDP(t), newFakeSearxng(t)
	sx.handler = func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL+"/search?"+r.URL.RawQuery, http.StatusFound)
	}
	s, mint := userTokenServer(t, idp, sx, true)

	if err := searchVia(t, s, "Bearer "+mint("alice")); err == nil {
		t.Error("a redirected token-bearing search succeeded")
	}
	if v := leaked.Load().(string); v != "" {
		t.Fatalf("user token followed the redirect to another host: %q", v)
	}
}

func TestSearch_FeatureOffSendsNothingAndKeepsNoToken(t *testing.T) {
	idp, sx := newFakeIDP(t), newFakeSearxng(t)
	s, mint := userTokenServer(t, idp, sx, false)

	var onCtx string
	h := s.requireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		onCtx = oauthTokenFromTokenInfo(auth.TokenInfoFromContext(r.Context()))
		_, _ = s.search(r.Context(), "q", 1, "", "all", "", 0, "")
	}))
	r := httptest.NewRequest(http.MethodPost, "/", nil)
	r.Header.Set("Authorization", "Bearer "+mint("alice"))
	h.ServeHTTP(httptest.NewRecorder(), r)

	if onCtx != "" {
		t.Error("the caller's token was kept on the context with the feature off")
	}
	if got := sx.seen(); len(got) != 1 || got[0] != "" {
		t.Errorf("SearXNG saw %q with the feature off", got)
	}
	if idp.calls.Load() != 0 {
		t.Error("identity provider called with the feature off")
	}
}

func TestSearch_TokensNeverLogged(t *testing.T) {
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(prev) })

	idp, sx := newFakeIDP(t), newFakeSearxng(t)
	s, mint := userTokenServer(t, idp, sx, true)
	alice := mint("alice")
	_ = searchVia(t, s, "Bearer "+alice) // success path
	_ = searchVia(t, s, "Bearer static-secret-0123456789abcdef")

	idp.respond = func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"invalid_grant"}`))
	}
	bob := mint("bob")
	_ = searchVia(t, s, "Bearer "+bob) // failure path

	logs := buf.String()
	for name, secret := range map[string]string{
		"alice's token": alice, "alice's backend token": backendTokenFor(alice),
		"bob's token": bob, "client secret": testUserTokenSecret,
	} {
		if strings.Contains(logs, secret) {
			t.Errorf("%s appears in the log", name)
		}
	}
	if !strings.Contains(logs, "user token exchange failed") {
		t.Error("the failed exchange was not logged")
	}
}

func TestSearch_MetricsExposeOutcomes(t *testing.T) {
	s := &Server{}
	s.metrics.UserToken[userTokenFailed].Add(2)
	w := httptest.NewRecorder()
	s.ServeMetrics(w, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if !strings.Contains(w.Body.String(), `mcp_searxng_user_token_total{outcome="failed"} 2`) {
		t.Errorf("metric missing:\n%s", w.Body.String())
	}
}

// ── end to end through the MCP HTTP stack ─────────────────────────────────────

// bearerTransport sets the Authorization header from a swappable token, so a
// test can change credentials mid-session the way a client refreshing its
// token would.
type bearerTransport struct {
	token atomic.Value
}

func (b *bearerTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("Authorization", "Bearer "+b.token.Load().(string))
	return http.DefaultTransport.RoundTrip(r)
}

// TestUserToken_EndToEndOverStreamableHTTP drives a real MCP client against
// the same handler chain main() builds. It proves what the unit tests above
// assume: the verified token on the HTTP request reaches the tool handler, and
// it is the token of *that* request — a refreshed token mid-session is used,
// never one remembered from the session's first request.
func TestUserToken_EndToEndOverStreamableHTTP(t *testing.T) {
	for _, stateless := range []bool{false, true} {
		name := "stateful"
		if stateless {
			name = "stateless"
		}
		t.Run(name, func(t *testing.T) {
			idp, sx := newFakeIDP(t), newFakeSearxng(t)
			s, mint := userTokenServer(t, idp, sx, true)
			s.config.Stateless = stateless

			handler := mcp.NewStreamableHTTPHandler(
				func(*http.Request) *mcp.Server { return s.mcpServer },
				&mcp.StreamableHTTPOptions{Stateless: stateless},
			)
			relay := httptest.NewServer(s.authGate(s.trackClientSession(s.limitSessions(handler))))
			t.Cleanup(relay.Close)

			bt := &bearerTransport{}
			first, refreshed := mint("alice"), mint("alice")
			bt.token.Store(first)

			ctx := context.Background()
			cs, err := mcp.NewClient(&mcp.Implementation{Name: "e2e", Version: "test"}, nil).Connect(ctx,
				&mcp.StreamableClientTransport{
					Endpoint:             relay.URL,
					HTTPClient:           &http.Client{Transport: bt},
					DisableStandaloneSSE: true,
					MaxRetries:           -1,
				}, nil)
			if err != nil {
				t.Fatalf("connect: %v", err)
			}
			t.Cleanup(func() { _ = cs.Close() })

			call := func() {
				t.Helper()
				res, err := cs.CallTool(ctx, &mcp.CallToolParams{
					Name: "searxng_web_search", Arguments: map[string]any{"query": "q"},
				})
				if err != nil || res.IsError {
					t.Fatalf("tool call: err=%v result=%+v", err, res)
				}
			}
			call()
			bt.token.Store(refreshed)
			call()

			got := sx.seen()
			want := []string{backendTokenFor(first), backendTokenFor(refreshed)}
			if len(got) != 2 || got[0] != want[0] || got[1] != want[1] {
				t.Fatalf("SearXNG saw %q, want %q", got, want)
			}
		})
	}
}

// TestUserToken_SessionBoundToUser pins the session binding withSDKTokenInfo
// buys: a session an OAuth user created cannot be driven by another OAuth user
// or by a static-token caller, even with the right Mcp-Session-Id. Without it,
// learning a session ID would be enough to search under its creator's
// identity, with their backend permissions.
func TestUserToken_SessionBoundToUser(t *testing.T) {
	idp, sx := newFakeIDP(t), newFakeSearxng(t)
	s, mint := userTokenServer(t, idp, sx, true)
	handler := mcp.NewStreamableHTTPHandler(
		func(*http.Request) *mcp.Server { return s.mcpServer }, nil)
	relay := httptest.NewServer(s.authGate(s.trackClientSession(s.limitSessions(handler))))
	t.Cleanup(relay.Close)

	post := func(authz, session, body string) *http.Response {
		t.Helper()
		req, _ := http.NewRequest(http.MethodPost, relay.URL, strings.NewReader(body))
		req.Header.Set("Authorization", authz)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json, text/event-stream")
		if session != "" {
			req.Header.Set("Mcp-Session-Id", session)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = resp.Body.Close() })
		return resp
	}

	alice := "Bearer " + mint("alice")
	resp := post(alice, "", `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}`)
	session := resp.Header.Get("Mcp-Session-Id")
	if resp.StatusCode != http.StatusOK || session == "" {
		t.Fatalf("initialize: status %d, session %q", resp.StatusCode, session)
	}
	call := `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"searxng_web_search","arguments":{"query":"q"}}}`

	for name, authz := range map[string]string{
		"another OAuth user": "Bearer " + mint("bob"),
		"a static token":     "Bearer static-secret-0123456789abcdef",
	} {
		if r := post(authz, session, call); r.StatusCode != http.StatusForbidden {
			t.Errorf("%s on alice's session: status %d, want 403", name, r.StatusCode)
		}
	}
	if n := sx.calls.Load(); n != 0 {
		t.Fatalf("a hijacked session reached SearXNG %d times", n)
	}
	if r := post("Bearer "+mint("alice"), session, call); r.StatusCode != http.StatusOK {
		t.Errorf("alice with a refreshed token on her own session: status %d, want 200", r.StatusCode)
	}
}
