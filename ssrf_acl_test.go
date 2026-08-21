package main

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// ── newFetchACL parsing ───────────────────────────────────────────────────────

func TestNewFetchACL_ValidInput(t *testing.T) {
	a, err := newFetchACL(
		[]string{"Confluence.Internal.:443", " wiki.corp:80 ", ""},
		[]string{"10.0.0.0/8:443", " 192.168.0.0/16:8443 "},
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !a.hostAllowed("confluence.internal", "443") {
		t.Error("expected confluence.internal:443 to be allowed (case/dot-normalised)")
	}
	if !a.hostAllowed("WIKI.CORP", "80") {
		t.Error("expected wiki.corp:80 to be allowed (trim + case-insensitive)")
	}
	if a.hostAllowed("evil.example.com", "443") {
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
	_, err := newFetchACL(nil, []string{"10.0.0.0/8:443", "not-a-cidr:443"})
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
	if err := a.assertReachable(net.ParseIP("10.1.2.3"), "443"); err == nil {
		t.Error("empty ACL should still block private IPs")
	}
	// A public IP passes.
	if err := a.assertReachable(net.ParseIP("93.184.216.34"), "443"); err != nil {
		t.Errorf("empty ACL should allow public IPs, got: %v", err)
	}
}

// ── assertReachable: CIDR override ────────────────────────────────────────────

func TestAssertReachable_AllowedCIDROverridesPrivateBlock(t *testing.T) {
	a, _ := newFetchACL(nil, []string{"10.0.0.0/8:443"})

	if err := a.assertReachable(net.ParseIP("10.20.30.40"), "443"); err != nil {
		t.Errorf("10.20.30.40:443 is inside allowed 10.0.0.0/8:443, want allow, got: %v", err)
	}
	// A private IP OUTSIDE the allowed range is still blocked.
	if err := a.assertReachable(net.ParseIP("192.168.1.1"), "443"); err == nil {
		t.Error("192.168.1.1 is outside the allowed range, want block")
	}
	// A public IP is unaffected.
	if err := a.assertReachable(net.ParseIP("1.1.1.1"), "443"); err != nil {
		t.Errorf("public IP should pass, got: %v", err)
	}
}

// The finding this closes on the CIDR side: an allowed range must not make
// every port on every address it covers reachable.
func TestAssertReachable_CIDRPortScoped(t *testing.T) {
	a, _ := newFetchACL(nil, []string{"10.0.0.0/8:443"})

	for _, port := range []string{"6379", "2379", "10250", "80", "22"} {
		if err := a.assertReachable(net.ParseIP("10.20.30.40"), port); err == nil {
			t.Errorf("10.20.30.40:%s is not on the allowed port, want block", port)
		}
	}
}

// Several entries naming the same range accumulate their ports rather than
// the later one replacing the earlier.
func TestNewFetchACL_CIDRPortsAccumulate(t *testing.T) {
	a, _ := newFetchACL(nil, []string{"10.0.0.0/8:80", "10.0.0.0/8:443"})
	if len(a.allowedCIDRs) != 1 {
		t.Fatalf("same range listed twice should collapse to one entry, got %d", len(a.allowedCIDRs))
	}
	for _, port := range []string{"80", "443"} {
		if err := a.assertReachable(net.ParseIP("10.1.2.3"), port); err != nil {
			t.Errorf("port %s should be allowed, got: %v", port, err)
		}
	}
	if err := a.assertReachable(net.ParseIP("10.1.2.3"), "6379"); err == nil {
		t.Error("an unlisted port must stay blocked")
	}
}

// A CIDR entry without a port is rejected at startup, for the same reason a
// bare hostname is — except the stakes are higher, since a range multiplies
// the unscoped-port exposure by every address it covers.
func TestNewFetchACL_CIDRWithoutPortRejected(t *testing.T) {
	for _, bad := range []string{"10.0.0.0/8", "fd00::/8", "10.1.2.3"} {
		if _, err := newFetchACL(nil, []string{bad}); err == nil {
			t.Errorf("CIDR entry %q without a port must be rejected, got nil error", bad)
		}
	}
}

// A default-route prefix is refused outright: it does not widen the address
// policy, it removes it. Checked for both families.
func TestNewFetchACL_DefaultRouteRefused(t *testing.T) {
	for _, bad := range []string{"0.0.0.0/0:443", "::/0:443"} {
		_, err := newFetchACL(nil, []string{bad})
		if err == nil {
			t.Fatalf("entry %q must be refused, got nil error", bad)
		}
		if !strings.Contains(err.Error(), "every address") {
			t.Errorf("error for %q should explain what it grants, got: %v", bad, err)
		}
	}
}

// The IPv6 form parses despite the address itself containing colons: the port
// is whatever follows the last colon after the slash, and a prefix length is
// digits only, so the split is exact.
func TestParseAllowedCIDREntry_IPv6(t *testing.T) {
	n, port, err := parseAllowedCIDREntry("fd00:1234::/64:8443")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := n.String(); got != "fd00:1234::/64" {
		t.Errorf("range = %q, want fd00:1234::/64", got)
	}
	if port != "8443" {
		t.Errorf("port = %q, want 8443", port)
	}
	a, _ := newFetchACL(nil, []string{"fd00:1234::/64:8443"})
	if err := a.assertReachable(net.ParseIP("fd00:1234::5"), "8443"); err != nil {
		t.Errorf("address inside the allowed v6 range should pass, got: %v", err)
	}
	if err := a.assertReachable(net.ParseIP("fd00:1234::5"), "6379"); err == nil {
		t.Error("an unlisted port in the v6 range must stay blocked")
	}
}

// cidrAddressCount is what the startup warning reports; a wrong number here
// would understate the blast radius in exactly the place an operator is
// relying on it.
func TestCIDRAddressCount(t *testing.T) {
	cases := map[string]string{
		"10.1.2.0/24:443":    "256",
		"10.0.0.0/8:443":     "16777216",
		"10.1.2.3/32:443":    "1",
		"fd00:1234::/64:443": "18446744073709551616",
	}
	for entry, want := range cases {
		n, _, err := parseAllowedCIDREntry(entry)
		if err != nil {
			t.Fatalf("%s: %v", entry, err)
		}
		if got := cidrAddressCount(n).String(); got != want {
			t.Errorf("cidrAddressCount(%s) = %s, want %s", entry, got, want)
		}
	}
}

func TestAssertReachable_IPv6AllowedCIDR(t *testing.T) {
	a, _ := newFetchACL(nil, []string{"fd00::/8:443"}) // ULA range
	if err := a.assertReachable(net.ParseIP("fd12:3456::1"), "443"); err != nil {
		t.Errorf("ULA address inside allowed fd00::/8 should pass, got: %v", err)
	}
	if err := a.assertReachable(net.ParseIP("fe80::1"), "443"); err == nil {
		t.Error("link-local fe80::1 outside allowed range should be blocked")
	}
}

// ── hostAllowed normalisation ─────────────────────────────────────────────────

func TestHostAllowed_Normalisation(t *testing.T) {
	a, _ := newFetchACL([]string{"jira.corp:443"}, nil)
	for _, in := range []string{"jira.corp", "JIRA.CORP", "jira.corp.", "  jira.corp  "} {
		if !a.hostAllowed(in, "443") {
			t.Errorf("hostAllowed(%q) = false, want true", in)
		}
	}
	if a.hostAllowed("sub.jira.corp", "443") {
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
	a, err := newFetchACL(nil, []string{"127.0.0.0/8:" + portOf(t, srv.URL)})
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

	// httptest serves on 127.0.0.1:PORT. Allow-list that exact authority; the
	// dial should now bypass the loopback block even with NO allowed CIDR.
	a, _ := newFetchACL([]string{authorityOf(t, srv.URL)}, nil)

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
	b, _ := newFetchACL([]string{"some.other.host:80"}, nil)
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
	a, _ := newFetchACL([]string{"127.0.0.1:80"}, nil) // entry host allowed

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
	a, _ := newFetchACL([]string{"127.0.0.1:80"}, nil)
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

// portOf extracts the port from a URL, for building a FETCH_ALLOWED_CIDRS
// entry against an httptest server's ephemeral port.
func portOf(t *testing.T, rawURL string) string {
	t.Helper()
	_, port, err := net.SplitHostPort(strings.TrimPrefix(rawURL, "http://"))
	if err != nil {
		t.Fatalf("could not split port from %q: %v", rawURL, err)
	}
	return port
}

// authorityOf extracts "host:port" from a URL, which is the form a
// FETCH_ALLOWED_HOSTS entry now takes.
func authorityOf(t *testing.T, rawURL string) string {
	t.Helper()
	// srv.URL looks like http://127.0.0.1:PORT
	trimmed := strings.TrimPrefix(rawURL, "http://")
	if _, _, err := net.SplitHostPort(trimmed); err != nil {
		t.Fatalf("could not split host:port from %q: %v", rawURL, err)
	}
	return trimmed
}

// ── Port scoping ──────────────────────────────────────────────────────────────
//
// A bare hostname allows every port (the historical behaviour, kept so an
// upgrade does not silently narrow a working allow-list). A "host:port" entry
// allows only that port, which is what stops "let the agent read the wiki"
// from also granting the Redis, etcd, or kubelet listener on the same machine.

func TestHostAllowed_PortScoped(t *testing.T) {
	a, err := newFetchACL([]string{"wiki.corp:8443"}, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !a.hostAllowed("wiki.corp", "8443") {
		t.Error("scoped entry should allow its own port")
	}
	for _, port := range []string{"6379", "2379", "10250", "443", "80"} {
		if a.hostAllowed("wiki.corp", port) {
			t.Errorf("scoped entry must not allow port %s", port)
		}
	}
}

// A bare hostname is rejected at startup rather than being read as "all
// ports". This is the property that makes the fix apply to every deployment
// instead of only the ones that opt in: an operator upgrading with a bare
// entry is stopped and told what to write, rather than silently keeping the
// wide allowance or silently losing access to a service on another port.
func TestNewFetchACL_BareHostnameRejected(t *testing.T) {
	_, err := newFetchACL([]string{"wiki.corp"}, nil)
	if err == nil {
		t.Fatal("a bare hostname must be rejected, got nil error")
	}
	msg := err.Error()
	for _, want := range []string{"wiki.corp", "host:port", "every port"} {
		if !strings.Contains(msg, want) {
			t.Errorf("error should mention %q so it is actionable, got: %v", want, err)
		}
	}
}

// A bare unbracketed IPv6 literal is also rejected — it has no port, and
// guessing where the address ends and a port begins is exactly the ambiguity
// the bracket form exists to remove.
func TestNewFetchACL_BareIPv6Rejected(t *testing.T) {
	for _, bad := range []string{"fd00::1", "[fd00::1]"} {
		if _, err := newFetchACL([]string{bad}, nil); err == nil {
			t.Errorf("bare IPv6 entry %q must be rejected, got nil error", bad)
		}
	}
}

// Several scoped entries for one host accumulate rather than overwrite.
func TestHostAllowed_MultipleScopedPorts(t *testing.T) {
	a, _ := newFetchACL([]string{"wiki.corp:443", "wiki.corp:8443"}, nil)
	if !a.hostAllowed("wiki.corp", "443") || !a.hostAllowed("wiki.corp", "8443") {
		t.Error("both listed ports should be allowed")
	}
	if a.hostAllowed("wiki.corp", "8080") {
		t.Error("an unlisted port must stay blocked")
	}
}

func TestParseAllowedHostEntry(t *testing.T) {
	cases := []struct {
		in       string
		wantHost string
		wantPort string
	}{
		{"confluence.corp:8443", "confluence.corp", "8443"},
		{"  Confluence.Corp.:8443  ", "confluence.corp", "8443"},
		{"CONFLUENCE.CORP:8443", "confluence.corp", "8443"},
		{"10.1.2.3:8080", "10.1.2.3", "8080"},
		{"[fd00::1]:8443", "fd00::1", "8443"},
	}
	for _, c := range cases {
		host, port, err := parseAllowedHostEntry(c.in)
		if err != nil {
			t.Errorf("parseAllowedHostEntry(%q) errored: %v", c.in, err)
			continue
		}
		if host != c.wantHost || port != c.wantPort {
			t.Errorf("parseAllowedHostEntry(%q) = (%q, %q), want (%q, %q)",
				c.in, host, port, c.wantHost, c.wantPort)
		}
	}
}

// A malformed entry stops startup rather than sitting in the allow-list
// matching nothing — the failure mode where an operator believes access was
// granted and the fetch fails far away from the config that caused it.
func TestNewFetchACL_InvalidHostEntryFailsLoud(t *testing.T) {
	for _, bad := range []string{
		"confluence.corp",         // no port at all
		"confluence.corp:",        // empty port
		"confluence.corp:https",   // non-numeric port
		"confluence.corp:0",       // out of range
		"confluence.corp:65536",   // out of range
		"https://confluence.corp", // a URL, not a host
		"confluence.corp/wiki",    // a path
	} {
		if _, err := newFetchACL([]string{bad}, nil); err == nil {
			t.Errorf("expected an error for entry %q, got nil", bad)
		}
	}
}

// The IPv6 forms have to agree with what the dialer and url.URL.Hostname
// actually hand to hostAllowed, which is the unbracketed literal.
func TestHostAllowed_IPv6Forms(t *testing.T) {
	a, _ := newFetchACL([]string{"[fd00::1]:8443"}, nil)
	if !a.hostAllowed("fd00::1", "8443") {
		t.Error("bracketed entry should match the unbracketed dial host")
	}
	if a.hostAllowed("fd00::1", "6379") {
		t.Error("scoped IPv6 entry must not allow other ports")
	}
}

// urlHostPort fills in the scheme default so a "wiki.corp:443" entry matches
// a plain https:// URL that never spells the port out.
func TestURLHostPort_SchemeDefaults(t *testing.T) {
	cases := []struct{ raw, host, port string }{
		{"https://wiki.corp/page", "wiki.corp", "443"},
		{"http://wiki.corp/page", "wiki.corp", "80"},
		{"https://wiki.corp:8443/page", "wiki.corp", "8443"},
		{"http://WIKI.CORP./page", "wiki.corp", "80"},
	}
	for _, c := range cases {
		u, err := url.Parse(c.raw)
		if err != nil {
			t.Fatalf("bad test URL %q: %v", c.raw, err)
		}
		host, port := urlHostPort(u)
		if host != c.host || port != c.port {
			t.Errorf("urlHostPort(%q) = (%q, %q), want (%q, %q)",
				c.raw, host, port, c.host, c.port)
		}
	}
}

// The end-to-end shape of the finding this scoping closes: an allow-listed
// wiki on 443 must not make every other port on that machine reachable.
func TestCheckRedirect_BlocksPortPivotOnAllowedHost(t *testing.T) {
	a, _ := newFetchACL([]string{"127.0.0.1:443"}, nil)

	// The allowed port passes.
	ok, _ := http.NewRequestWithContext(context.Background(), "GET", "https://127.0.0.1/page", nil)
	if err := a.safeCheckRedirect(ok, nil); err != nil {
		t.Errorf("redirect to the allow-listed port should pass, got: %v", err)
	}

	// A redirect to a different port on the same allow-listed host falls back
	// to the per-IP policy, which blocks loopback.
	pivot, _ := http.NewRequestWithContext(context.Background(), "GET", "http://127.0.0.1:6379/", nil)
	if err := a.safeCheckRedirect(pivot, nil); err == nil {
		t.Fatal("redirect to an unlisted port on an allow-listed host should be blocked")
	}
}
