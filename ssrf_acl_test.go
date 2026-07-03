package main

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// ── newFetchACL parsing ───────────────────────────────────────────────────────

func TestNewFetchACL_ValidInput(t *testing.T) {
	a, err := newFetchACL(
		[]string{"Confluence.Internal.", " wiki.corp ", ""},
		[]string{"10.0.0.0/8", " 192.168.0.0/16 "},
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !a.hostAllowed("confluence.internal") {
		t.Error("expected confluence.internal to be allowed (case/dot-normalised)")
	}
	if !a.hostAllowed("WIKI.CORP") {
		t.Error("expected wiki.corp to be allowed (trim + case-insensitive)")
	}
	if a.hostAllowed("evil.example.com") {
		t.Error("did not expect evil.example.com to be allowed")
	}
	if len(a.allowedCIDRs) != 2 {
		t.Fatalf("expected 2 CIDRs, got %d", len(a.allowedCIDRs))
	}
	if a.isEmpty() {
		t.Error("acl should not report empty")
	}
}

func TestNewFetchACL_InvalidCIDRFailsLoud(t *testing.T) {
	_, err := newFetchACL(nil, []string{"10.0.0.0/8", "not-a-cidr"})
	if err == nil {
		t.Fatal("expected an error for malformed CIDR, got nil")
	}
	if !strings.Contains(err.Error(), "not-a-cidr") {
		t.Errorf("error should name the bad entry, got: %v", err)
	}
}

func TestEmptyFetchACL_BehavesStrict(t *testing.T) {
	a := emptyFetchACL()
	if !a.isEmpty() {
		t.Error("emptyFetchACL should report empty")
	}
	// A private IP must still be rejected by assertReachable when no CIDR is allowed.
	if err := a.assertReachable(net.ParseIP("10.1.2.3")); err == nil {
		t.Error("empty ACL should still block private IPs")
	}
	// A public IP passes.
	if err := a.assertReachable(net.ParseIP("93.184.216.34")); err != nil {
		t.Errorf("empty ACL should allow public IPs, got: %v", err)
	}
}

// ── assertReachable: CIDR override ────────────────────────────────────────────

func TestAssertReachable_AllowedCIDROverridesPrivateBlock(t *testing.T) {
	a, _ := newFetchACL(nil, []string{"10.0.0.0/8"})

	if err := a.assertReachable(net.ParseIP("10.20.30.40")); err != nil {
		t.Errorf("10.20.30.40 is inside allowed 10.0.0.0/8, want allow, got: %v", err)
	}
	// A private IP OUTSIDE the allowed range is still blocked.
	if err := a.assertReachable(net.ParseIP("192.168.1.1")); err == nil {
		t.Error("192.168.1.1 is outside the allowed range, want block")
	}
	// A public IP is unaffected.
	if err := a.assertReachable(net.ParseIP("1.1.1.1")); err != nil {
		t.Errorf("public IP should pass, got: %v", err)
	}
}

func TestAssertReachable_IPv6AllowedCIDR(t *testing.T) {
	a, _ := newFetchACL(nil, []string{"fd00::/8"}) // ULA range
	if err := a.assertReachable(net.ParseIP("fd12:3456::1")); err != nil {
		t.Errorf("ULA address inside allowed fd00::/8 should pass, got: %v", err)
	}
	if err := a.assertReachable(net.ParseIP("fe80::1")); err == nil {
		t.Error("link-local fe80::1 outside allowed range should be blocked")
	}
}

// ── hostAllowed normalisation ─────────────────────────────────────────────────

func TestHostAllowed_Normalisation(t *testing.T) {
	a, _ := newFetchACL([]string{"jira.corp"}, nil)
	for _, in := range []string{"jira.corp", "JIRA.CORP", "jira.corp.", "  jira.corp  "} {
		if !a.hostAllowed(in) {
			t.Errorf("hostAllowed(%q) = false, want true", in)
		}
	}
	if a.hostAllowed("sub.jira.corp") {
		t.Error("exact-match allow-list must not match subdomains")
	}
}

// ── Live dial tests: the real proof ───────────────────────────────────────────
//
// These stand up a loopback HTTP server (127.0.0.1) and drive the real
// safeDialContext / safeCheckRedirect through an *http.Client, exactly as the
// server wires them. 127.0.0.1 is normally blocked (IsLoopback); the tests
// show it goes through ONLY when the operator allow-lists the host or a CIDR
// covering the loopback address.

func clientFor(a *fetchACL) *http.Client {
	return &http.Client{
		Transport:     &http.Transport{Proxy: nil, DialContext: a.safeDialContext},
		CheckRedirect: a.safeCheckRedirect,
	}
}

func TestLiveDial_DefaultBlocksLoopback(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer srv.Close()

	// Default (empty) ACL: the loopback dial must fail at the dialer.
	_, err := clientFor(emptyFetchACL()).Get(srv.URL)
	if err == nil {
		t.Fatal("expected loopback fetch to be blocked by default, but it succeeded")
	}
	if !strings.Contains(err.Error(), "non-public") {
		t.Logf("blocked as expected (message: %v)", err)
	}
}

func TestLiveDial_AllowedCIDRLetsLoopbackThrough(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(204)
	}))
	defer srv.Close()

	// Allow the loopback range explicitly.
	a, err := newFetchACL(nil, []string{"127.0.0.0/8"})
	if err != nil {
		t.Fatal(err)
	}
	resp, err := clientFor(a).Get(srv.URL)
	if err != nil {
		t.Fatalf("expected allowed-CIDR fetch to succeed, got: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 204 {
		t.Errorf("status = %d, want 204", resp.StatusCode)
	}
}

func TestLiveDial_AllowedHostLetsLoopbackThrough(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer srv.Close()

	// httptest serves on 127.0.0.1:PORT — the URL host is the literal
	// "127.0.0.1". Allow-list that host by name; the dial should now bypass
	// the loopback block even with NO allowed CIDR.
	host := hostOf(t, srv.URL) // "127.0.0.1"
	a, _ := newFetchACL([]string{host}, nil)

	resp, err := clientFor(a).Get(srv.URL)
	if err != nil {
		t.Fatalf("expected allowed-host fetch to succeed, got: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}

	// Sanity: a DIFFERENT host name that resolves to loopback is still blocked.
	// "localhost" also resolves to 127.0.0.1 but is not on the allow-list.
	b, _ := newFetchACL([]string{"some.other.host"}, nil)
	altURL := strings.Replace(srv.URL, "127.0.0.1", "localhost", 1)
	if _, err := clientFor(b).Get(altURL); err == nil {
		t.Error("localhost (not allow-listed) resolving to loopback should be blocked")
	}
}

// ── Redirect re-validation ────────────────────────────────────────────────────
//
// A public-looking (here: allowed) entry point must not become a pivot to a
// blocked internal address via redirect. We drive safeCheckRedirect directly.

func TestCheckRedirect_BlocksNonAllowedInternalHop(t *testing.T) {
	a, _ := newFetchACL([]string{"127.0.0.1"}, nil) // entry host allowed

	// Redirect target "localhost" resolves to loopback but is not allow-listed
	// and 127.0.0.0/8 is not in an allowed CIDR → must be blocked.
	req, _ := http.NewRequestWithContext(context.Background(), "GET", "http://localhost/admin", nil)
	err := a.safeCheckRedirect(req, nil)
	if err == nil {
		t.Fatal("redirect to non-allow-listed loopback host should be blocked")
	}
	if !strings.Contains(err.Error(), "redirect blocked") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestCheckRedirect_AllowsAllowListedHop(t *testing.T) {
	a, _ := newFetchACL([]string{"127.0.0.1"}, nil)
	req, _ := http.NewRequestWithContext(context.Background(), "GET", "http://127.0.0.1/next", nil)
	if err := a.safeCheckRedirect(req, nil); err != nil {
		t.Errorf("redirect to allow-listed host should pass, got: %v", err)
	}
}

func TestCheckRedirect_StopsAfterFiveHops(t *testing.T) {
	a := emptyFetchACL()
	req, _ := http.NewRequestWithContext(context.Background(), "GET", "http://example.com/", nil)
	via := make([]*http.Request, 5)
	if err := a.safeCheckRedirect(req, via); err == nil {
		t.Error("expected redirect chain to stop after 5 hops")
	}
}

// hostOf extracts the host (no port) from a URL for test convenience.
func hostOf(t *testing.T, rawURL string) string {
	t.Helper()
	// srv.URL looks like http://127.0.0.1:PORT
	trimmed := strings.TrimPrefix(rawURL, "http://")
	host, _, err := net.SplitHostPort(trimmed)
	if err != nil {
		t.Fatalf("could not split host from %q: %v", rawURL, err)
	}
	return host
}
