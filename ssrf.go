// Package main: ssrf.go — SSRF protection for the URL-fetch tool.
//
// This file is the single place to read when auditing the project's
// server-side request forgery defences. The same checks run at TCP-dial
// time (safeDialContext) and again on every redirect hop
// (safeCheckRedirect), so an attacker who controls DNS for a public-
// looking host cannot rebind to an internal address between the check
// and the connect, and cannot pivot via an open redirect on a public
// host either.
//
// Coverage is split into two layers:
//
//  1. Stdlib predicates (IsLoopback, IsLinkLocalUnicast,
//     IsLinkLocalMulticast, IsPrivate, IsUnspecified, IsMulticast,
//     !IsGlobalUnicast) — short, well-tested, covers the common cases.
//  2. A hardcoded list of reserved CIDR blocks the predicates miss
//     (reservedCIDRs), each annotated with the RFC that reserves it so
//     the list can be diffed against IANA's special-purpose registries
//     by hand.
//
// The reason an address was rejected is logged at debug level only — it
// must not appear in responses returned to MCP callers, since that
// would let an attacker probe internal network layout via error text.
package main

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// ── Fetch allow-list (operator-widened SSRF policy) ───────────────────────────
//
// By default the fetch tool may only reach globally-routable public unicast
// addresses (see assertPublicIP).  That is the correct default for a service
// that fetches attacker-influenced URLs.  Some operators, however, run the
// relay inside a trusted network and *want* it to read internal resources —
// a self-hosted Confluence, Jira, GitLab, wiki, or an internal docs host.
//
// fetchACL carries two opt-in allowances, both empty by default (so the
// default behaviour is byte-for-byte unchanged):
//
//   - allowedHosts: exact hostnames whose fetches skip the public-IP check
//     entirely.  Matched against the *request* hostname (and re-checked on
//     every redirect hop), not against a resolved IP, so an operator can
//     name an internal host without pinning its address.  The caller cannot
//     forge this — the hostname comes from the URL an authenticated caller
//     asked for — and the operator controls DNS for their own names, so
//     this does not reopen the DNS-rebinding hole the dialer closes for the
//     default path.
//
//     Every entry MUST name a port ("confluence.corp:8443"); the allowance
//     covers that port and nothing else.  A bare hostname is a startup
//     error, not a shorthand for "all ports", because allow-listing a
//     hostname alone also exposes whatever else that machine happens to be
//     listening on — Redis on 6379, etcd on 2379, a kubelet on 10250 —
//     which is never what "let the agent read our wiki" was meant to
//     grant.  Requiring the port makes the operator state the reach they
//     actually intend instead of inheriting the widest possible one from a
//     default.
//
//     Rejecting the bare form at startup rather than reinterpreting it as
//     some default port is deliberate.  A silent reinterpretation would
//     leave an entry that still parses but no longer matches, and the
//     failure would surface at fetch time far from the config that caused
//     it — the worst failure mode available for an allow-list, and the one
//     the malformed-entry check below already exists to prevent.
//
//   - allowedCIDRs: IP ranges that are treated as reachable even though the
//     default policy (IsPrivate / reserved / etc.) would block them.  This
//     is checked against the *resolved* IP at dial time and on each redirect
//     hop, so it is robust against rebinding: an attacker who rebinds a
//     public-looking name to a private IP is still blocked unless that exact
//     IP falls inside a range the operator explicitly listed.
//
// The two are independent (OR semantics): a fetch is permitted if its host
// is allow-listed OR its resolved IP is public OR its resolved IP is inside
// an allowed CIDR.  An allowed CIDR overrides *all* default blocks for the
// addresses it covers, including loopback/link-local — listing a range is an
// explicit operator statement that the range is safe to reach.  Keep the
// ranges tight; in particular do not list 169.254.0.0/16 unless you truly
// intend to expose the cloud metadata endpoint.
type fetchACL struct {
	allowedHosts map[string]allowedPorts // lower-cased, trailing-dot-stripped exact matches
	allowedCIDRs []*net.IPNet

	// Egress proxy for the fetch tool (FETCH_PROXY / FETCH_PROXY_ALL).
	// nil proxyURL means no proxy — the historical behaviour, in which
	// every fetch is dialled directly by safeDialContext.  See the
	// "Egress proxy" section below for the security rationale.
	proxyURL *url.URL
	// proxyAuthority is the canonical "host:port" of proxyURL with the
	// scheme's default port filled in, lower-cased.  It is compared
	// against the addr safeDialContext receives (which always carries an
	// explicit port) to recognise a dial that is heading for the proxy.
	proxyAuthority string
	proxyAll       bool
}

// allowedPorts is the set of ports allow-listed for one hostname.  There is
// no "any port" member by construction: newFetchACL rejects an entry that
// does not name a port, so the widest reach an operator can express for a
// host is the set of ports they wrote down.
type allowedPorts map[string]struct{}

// newFetchACL compiles the operator-supplied host and CIDR allow-lists.
// Host entries are normalised (trimmed, lower-cased, trailing FQDN dot
// removed) and must be written "host:port".  Every host entry and every CIDR
// must parse; a malformed entry returns an error so startup fails loudly
// rather than silently leaving a control mis-scoped — a typo in a security
// control should stop the server, not degrade it quietly.
//
// Several entries may name the same host, in which case their ports
// accumulate: "wiki.corp:80,wiki.corp:443" allows exactly those two.
func newFetchACL(hosts, cidrs []string) (*fetchACL, error) {
	a := &fetchACL{allowedHosts: make(map[string]allowedPorts, len(hosts))}
	for _, raw := range hosts {
		if strings.TrimSpace(raw) == "" {
			continue
		}
		host, port, err := parseAllowedHostEntry(raw)
		if err != nil {
			return nil, fmt.Errorf("FETCH_ALLOWED_HOSTS: %w", err)
		}
		if a.allowedHosts[host] == nil {
			a.allowedHosts[host] = make(allowedPorts, 1)
		}
		a.allowedHosts[host][port] = struct{}{}
	}
	for _, c := range cidrs {
		c = strings.TrimSpace(c)
		if c == "" {
			continue
		}
		_, n, err := net.ParseCIDR(c)
		if err != nil {
			return nil, fmt.Errorf("FETCH_ALLOWED_CIDRS: invalid CIDR %q: %w", c, err)
		}
		a.allowedCIDRs = append(a.allowedCIDRs, n)
	}
	return a, nil
}

// emptyFetchACL returns an ACL with no allowances — identical behaviour to
// the original public-only policy.  Used as the nil-safe default so a Server
// constructed directly in tests (with a zero Config) keeps strict semantics.
func emptyFetchACL() *fetchACL {
	return &fetchACL{allowedHosts: map[string]allowedPorts{}}
}

// isEmpty reports whether any allowance is configured. Used by the startup
// banner to decide whether to emit the "SSRF policy widened" audit warning.
func (a *fetchACL) isEmpty() bool {
	return len(a.allowedHosts) == 0 && len(a.allowedCIDRs) == 0
}

// normaliseHost lower-cases, trims, and strips a single trailing FQDN dot so
// that "Confluence.Internal." and "confluence.internal" compare equal.
func normaliseHost(h string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(h), "."))
}

// parseAllowedHostEntry splits one FETCH_ALLOWED_HOSTS entry into a
// normalised hostname and its port.  The port is mandatory.
//
// Accepted forms:
//
//	confluence.corp:8443   hostname with port
//	10.1.2.3:8080          IPv4 literal with port
//	[fd00::1]:8443         IPv6 literal with port (brackets required, as in a URL)
//
// Everything else is an error: a bare hostname, an empty or non-numeric or
// out-of-range port, a value carrying a scheme or a path.  Each returns a
// message naming the offending entry and the form that was wanted, so the
// operator can fix it without counting commas through an env var.
//
// The strictness is the point.  An allow-list line that parses but can never
// match is the worst outcome available here: the operator believes they
// granted access, the fetch fails at request time, and the reason is nowhere
// near the config that caused it.  Failing at startup puts the error next to
// the mistake.
func parseAllowedHostEntry(raw string) (host, port string, err error) {
	entry := strings.TrimSpace(raw)

	if strings.Contains(entry, "/") {
		return "", "", fmt.Errorf("entry %q looks like a URL; write host:port only "+
			"(e.g. \"confluence.corp:8443\")", raw)
	}

	// SplitHostPort handles "host:port" and "[v6]:port". It fails for a bare
	// hostname ("missing port") and for a bare unbracketed IPv6 literal ("too
	// many colons"); both are entries we want to reject, so its error is the
	// discrimination we need rather than something to work around.
	h, p, splitErr := net.SplitHostPort(entry)
	if splitErr != nil {
		return "", "", fmt.Errorf("entry %q has no port; write host:port "+
			"(e.g. \"confluence.corp:443\" for https, \"confluence.corp:8090\" for a "+
			"service on another port). A bare hostname is rejected because it would "+
			"allow every port on that host, including anything else it happens to be "+
			"serving. IPv6 literals need brackets: \"[fd00::1]:8443\"", raw)
	}
	if err := validatePort(p, raw); err != nil {
		return "", "", err
	}
	return normaliseHost(h), p, nil
}

// validatePort rejects the port spellings that would produce an entry no
// request can ever match.  raw is echoed in the error so the operator can
// find the offending line without counting commas.
func validatePort(port, raw string) error {
	if port == "" {
		return fmt.Errorf("entry %q has an empty port; name one, "+
			"e.g. \"confluence.corp:8443\"", raw)
	}
	n, convErr := strconv.Atoi(port)
	if convErr != nil || n < 1 || n > 65535 {
		return fmt.Errorf("entry %q has an invalid port %q; want a number in 1-65535", raw, port)
	}
	return nil
}

// hostAllowed reports whether host:port was explicitly allow-listed by the
// operator.  port is the concrete port the connection is heading for, with
// the scheme default already filled in by the caller, so an entry written as
// "wiki.corp:443" matches a plain https:// URL for that host and the operator
// does not have to spell the port out in every URL.
func (a *fetchACL) hostAllowed(host, port string) bool {
	if len(a.allowedHosts) == 0 {
		return false
	}
	ports, ok := a.allowedHosts[normaliseHost(host)]
	if !ok {
		return false
	}
	_, ok = ports[port]
	return ok
}

// ipInAllowedCIDR reports whether ip falls inside any operator-allowed range.
// net.IPNet.Contains normalises v4/v6 representations internally, matching the
// behaviour matchReservedCIDR already relies on.
func (a *fetchACL) ipInAllowedCIDR(ip net.IP) bool {
	for _, n := range a.allowedCIDRs {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// assertReachable is the per-IP gate for the default (non-host-allow-listed)
// path.  An operator-allowed CIDR wins over every default block; otherwise the
// standard public-only policy applies.
func (a *fetchACL) assertReachable(ip net.IP) error {
	if a.ipInAllowedCIDR(ip) {
		slog.Debug("SSRF: address in operator-allowed CIDR", "ip", ip)
		return nil
	}
	return assertPublicIP(ip)
}

// ── Egress proxy (opt-in) ────────────────────────────────────────────────────
//
// Some networks give the relay no direct route outward, or no route to a
// particular internal segment; the only way out is an HTTP/SOCKS forward
// proxy.  Two env vars opt in, both empty/false by default so the historical
// behaviour is byte-for-byte unchanged:
//
//   - FETCH_PROXY: the proxy URL.  On its own it applies *only* to hosts on
//     FETCH_ALLOWED_HOSTS.  This costs nothing in enforcement, because
//     safeDialContext already skips every per-IP check for allow-listed
//     hosts (see the hostAllowed branch below) — the operator has already
//     declared those names trusted.  Every other fetch continues to be
//     dialled directly with the full public-IP policy applied.
//
//   - FETCH_PROXY_ALL: route *every* fetch through the proxy.  This is for
//     networks with no direct egress at all, where the alternative is not
//     "stricter" but "nothing works".  It is a genuine delegation and must
//     be understood as one: once the proxy performs the connection it also
//     performs the DNS resolution, so the relay never learns the
//     destination IP and assertPublicIP / allowedCIDRs stop participating
//     entirely.  The egress proxy becomes the enforcement point.  main()
//     emits a warn-level audit line and the startup banner says so.
//
// Deliberately NOT read from HTTP_PROXY / HTTPS_PROXY.  Those are ambient —
// set by base images, CI, and cluster admission controllers for unrelated
// reasons — and honouring them here would let a variable nobody set for this
// purpose silently change a security control.  They also carry the opposite
// default (proxy everything except NO_PROXY) to this subsystem's default-deny
// stance.  searchTransport still honours them, because its single destination
// is operator-controlled and carries no SSRF exposure.

// proxyDefaultPort returns the port a scheme implies when the proxy URL
// omits one, so proxyAuthority can be compared against the always-explicit
// addr that http.Transport hands to DialContext.
func proxyDefaultPort(scheme string) string {
	switch scheme {
	case "https":
		return "443"
	case "socks5", "socks5h":
		return "1080"
	default:
		return "80"
	}
}

// setProxy validates and installs the operator's proxy configuration.
// Every failure mode returns an error so startup aborts loudly, matching
// newFetchACL's stance: a typo in a security-relevant control should stop
// the server rather than quietly change its reach.
func (a *fetchACL) setProxy(raw string, all bool) error {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		if all {
			return fmt.Errorf("FETCH_PROXY_ALL is set but FETCH_PROXY is empty: there is no proxy to route through")
		}
		return nil
	}
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("FETCH_PROXY: invalid URL %q: %w", raw, err)
	}
	switch u.Scheme {
	case "http", "https", "socks5", "socks5h":
	default:
		return fmt.Errorf("FETCH_PROXY: unsupported scheme %q (want http, https, socks5 or socks5h)", u.Scheme)
	}
	if u.Hostname() == "" {
		return fmt.Errorf("FETCH_PROXY: URL %q has no host", raw)
	}
	port := u.Port()
	if port == "" {
		port = proxyDefaultPort(u.Scheme)
	}
	a.proxyURL = u
	a.proxyAuthority = net.JoinHostPort(normaliseHost(u.Hostname()), port)
	a.proxyAll = all
	return nil
}

// proxyConfigured reports whether an egress proxy is in use.
func (a *fetchACL) proxyConfigured() bool { return a.proxyURL != nil }

// describeProxy renders the proxy setting for the startup banner, with any
// userinfo password redacted by url.URL.Redacted.
func (a *fetchACL) describeProxy() string {
	if a.proxyURL == nil {
		return "disabled"
	}
	scope := "allow-listed hosts only"
	if a.proxyAll {
		scope = "ALL fetches — per-IP SSRF checks delegated to the proxy"
	}
	return a.proxyURL.Redacted() + " (" + scope + ")"
}

// isProxyAuthority reports whether host:port names the configured proxy.
func (a *fetchACL) isProxyAuthority(host, port string) bool {
	if a.proxyAuthority == "" {
		return false
	}
	return net.JoinHostPort(normaliseHost(host), port) == a.proxyAuthority
}

// urlHostPort returns the normalised hostname and the concrete port a request
// URL targets, filling in the scheme default when the URL omits the port.
//
// Every allow-list decision goes through this so that "wiki.corp:443" on the
// allow-list matches a plain "https://wiki.corp/page" request.  Comparing
// against u.Port() directly would leave the scoped form matching only URLs
// that spell the port out, which is not how anyone writes them.
func urlHostPort(u *url.URL) (host, port string) {
	port = u.Port()
	if port == "" {
		if u.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	return normaliseHost(u.Hostname()), port
}

// requestAuthority returns the canonical "host:port" a request URL targets,
// filling in the scheme default when the URL omits the port.
func requestAuthority(u *url.URL) string {
	return net.JoinHostPort(urlHostPort(u))
}

// proxyFor is used as http.Transport.Proxy for the fetchClient.  Returning
// (nil, nil) means "dial this one directly", which leaves safeDialContext's
// per-IP policy fully in force — so the default path is unchanged whenever
// no proxy is configured.
//
// Returning an error fails the request. The one case that does so is a
// caller asking to fetch the proxy itself: without that guard the dial-time
// exemption below (which exists so the proxy is reachable even when it lives
// on a private address) would double as a way for an authenticated caller to
// reach the proxy's own listener directly, and an open forward proxy reached
// that way is equivalent to FETCH_PROXY_ALL for whoever found it.
func (a *fetchACL) proxyFor(req *http.Request) (*url.URL, error) {
	if a.proxyURL == nil {
		return nil, nil
	}
	if a.proxyAuthority == requestAuthority(req.URL) {
		return nil, fmt.Errorf("refusing to fetch the configured egress proxy")
	}
	if a.proxyAll || a.hostAllowed(urlHostPort(req.URL)) {
		return a.proxyURL, nil
	}
	return nil, nil
}

// safeDialContext is used as http.Transport.DialContext for the fetchClient.
// It resolves the hostname itself and rejects any address that is not a
// globally routable unicast IP — see assertPublicIP for the full block list
// — *at TCP-dial time*.
//
// Placing the check here (rather than in a pre-flight before http.Client.Do)
// closes the DNS-rebinding window: an attacker cannot swap the DNS answer
// between our check and the actual TCP connection.
func (a *fetchACL) safeDialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("invalid address %q: %w", addr, err)
	}

	// When Transport.Proxy selects a proxy, Go calls this dialer with the
	// *proxy's* address rather than the target's.  Naming a proxy in
	// FETCH_PROXY is itself the operator's statement that the address is
	// safe to reach, so requiring them to also list it in
	// FETCH_ALLOWED_CIDRS would be redundant friction — and in practice
	// invites the far worse workaround of allow-listing 10.0.0.0/8 wholesale.
	// proxyFor refuses target URLs that name the proxy, so this exemption
	// cannot be reached by a caller-supplied URL.  Dial addr as given, using
	// the stdlib's own address traversal.
	if a.isProxyAuthority(host, port) {
		slog.Debug("SSRF: dialing configured egress proxy", "authority", a.proxyAuthority)
		dialer := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
		return dialer.DialContext(ctx, network, addr)
	}

	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve host %q: %w", host, err)
	}
	if len(addrs) == 0 {
		return nil, fmt.Errorf("no addresses resolved for host %q", host)
	}

	// An operator-allow-listed hostname skips the per-IP public-address
	// check: the operator has explicitly declared this name reachable (e.g.
	// an internal Confluence/Jira/wiki host).  We still resolve here and dial
	// a concrete IP below rather than re-resolving, preserving the
	// no-rebinding-window discipline of the default path.
	if a.hostAllowed(host, port) {
		slog.Debug("SSRF: host on allow-list, skipping public-IP check",
			"host", host, "port", port)
	} else {
		for _, ia := range addrs {
			if err := a.assertReachable(ia.IP); err != nil {
				return nil, err
			}
		}
	}

	// Dial the first resolved IP directly to avoid a second DNS round-trip.
	dialer := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	return dialer.DialContext(ctx, network, net.JoinHostPort(addrs[0].IP.String(), port))
}

// safeCheckRedirect is used as http.Client.CheckRedirect for the fetchClient.
// It re-validates the redirect destination before following, so an open
// redirect on a public host cannot be used to pivot to an internal service.
// Uses the request context so the lookup is cancelled if the parent times out.
func (a *fetchACL) safeCheckRedirect(req *http.Request, via []*http.Request) error {
	if len(via) >= 5 {
		return fmt.Errorf("stopped after 5 redirects")
	}
	host, port := urlHostPort(req.URL)
	// Same allow-list semantics as the dialer: a redirect *to* an
	// allow-listed host:port is permitted regardless of the IP it resolves
	// to, while every other host is re-validated per resolved IP so an open
	// redirect on a public host still cannot pivot to a blocked internal one.
	// Carrying the port through matters here as much as at dial time: a
	// redirect is the cheapest way to turn an allowed "wiki.corp:443" into
	// a request for "wiki.corp:6379" if only the hostname were checked.
	if a.hostAllowed(host, port) {
		return nil
	}
	// Under FETCH_PROXY_ALL the proxy performs the connection and therefore
	// the DNS resolution; an IP we resolve here constrains nothing it will
	// do.  Worse, such networks frequently give the relay no working
	// resolver at all, so this lookup would fail and block legitimate
	// redirects.  Enforcement for redirect targets belongs to the proxy,
	// consistent with the rest of the FETCH_PROXY_ALL delegation.  The hop
	// limit above still applies.
	if a.proxyAll {
		return nil
	}
	addrs, err := net.DefaultResolver.LookupIPAddr(req.Context(), host)
	if err != nil {
		return fmt.Errorf("failed to resolve redirect host: %w", err)
	}
	for _, ia := range addrs {
		if err := a.assertReachable(ia.IP); err != nil {
			return fmt.Errorf("redirect blocked: %w", err)
		}
	}
	return nil
}

// reservedCIDRs lists IP ranges that are not globally routable but are NOT
// caught by the stdlib predicates (IsLoopback / IsLinkLocal* / IsPrivate /
// IsUnspecified / IsMulticast / IsGlobalUnicast).  Each entry cites the RFC
// that reserves it so the list can be audited against IANA's special-purpose
// registries directly.
//
// Stdlib coverage we deliberately rely on rather than duplicate here:
//
//	IsLoopback              127.0.0.0/8, ::1/128
//	IsLinkLocalUnicast      169.254.0.0/16, fe80::/10
//	IsLinkLocalMulticast    224.0.0.0/24, ff02::/16
//	IsPrivate               10/8, 172.16/12, 192.168/16, fc00::/7 (ULA)
//	IsUnspecified           0.0.0.0/32, ::/128
//	IsMulticast             224.0.0.0/4, ff00::/8
//	!IsGlobalUnicast        IPv4 directed broadcast + the above
var reservedCIDRs = mustParseCIDRs([]string{
	// ── IPv4 ─────────────────────────────────────────────────────────────────
	"0.0.0.0/8",       // RFC 1122 — "this network" (full /8; IsUnspecified only matches /32)
	"100.64.0.0/10",   // RFC 6598 — CGNAT / shared address space
	"192.0.0.0/24",    // RFC 6890 — IETF protocol assignments
	"192.0.2.0/24",    // RFC 5737 — TEST-NET-1
	"192.88.99.0/24",  // RFC 7526 — deprecated 6to4 anycast
	"198.18.0.0/15",   // RFC 2544 — benchmark testing
	"198.51.100.0/24", // RFC 5737 — TEST-NET-2
	"203.0.113.0/24",  // RFC 5737 — TEST-NET-3
	"240.0.0.0/4",     // RFC 1112 — reserved for future use (covers 255.255.255.255 limited broadcast)

	// ── IPv6 ─────────────────────────────────────────────────────────────────
	"64:ff9b::/96",   // RFC 6052 — NAT64 well-known prefix
	"64:ff9b:1::/48", // RFC 8215 — NAT64 local-use prefix
	"100::/64",       // RFC 6666 — discard-only address block
	"2001::/32",      // RFC 4380 — Teredo tunnelling
	"2001:2::/48",    // RFC 5180 — IPv6 benchmarking
	"2001:10::/28",   // RFC 4843 — deprecated ORCHID
	"2001:20::/28",   // RFC 7343 — ORCHIDv2
	"2001:db8::/32",  // RFC 3849 — documentation prefix
	"2002::/16",      // RFC 3056 — 6to4
})

func mustParseCIDRs(ss []string) []*net.IPNet {
	out := make([]*net.IPNet, 0, len(ss))
	for _, s := range ss {
		_, n, err := net.ParseCIDR(s)
		if err != nil {
			panic("invalid CIDR in reservedCIDRs " + s + ": " + err.Error())
		}
		out = append(out, n)
	}
	return out
}

// matchReservedCIDR returns the first reserved CIDR that contains ip, or nil
// if none does.
func matchReservedCIDR(ip net.IP) *net.IPNet {
	for _, n := range reservedCIDRs {
		if n.Contains(ip) {
			return n
		}
	}
	return nil
}

// assertPublicIP returns a generic error if ip is not a globally routable
// address.  The check has two layers: stdlib predicates first (covering the
// common cases concisely), then a hardcoded list of reserved CIDR blocks
// that the predicates miss (CGNAT, TEST-NET, benchmark, NAT64, Teredo, 6to4,
// IPv6 documentation, etc).  The reason an address was rejected is logged
// at debug level only — it must not appear in responses returned to MCP
// callers, since that would let an attacker probe internal network layout.
func assertPublicIP(ip net.IP) error {
	var kind string
	switch {
	case ip.IsLoopback():
		kind = "loopback"
	case ip.IsLinkLocalUnicast(), ip.IsLinkLocalMulticast():
		kind = "link-local"
	case ip.IsPrivate():
		kind = "private"
	case ip.IsUnspecified():
		kind = "unspecified"
	case ip.IsMulticast():
		kind = "multicast"
	case !ip.IsGlobalUnicast():
		// Catches IPv4 directed broadcast and any non-global-unicast that
		// the stdlib distinguishes but does not expose under a named predicate.
		kind = "non-global-unicast"
	default:
		if n := matchReservedCIDR(ip); n != nil {
			kind = "reserved (" + n.String() + ")"
			break
		}
		return nil
	}
	slog.Debug("SSRF: blocked non-public address", "ip", ip, "kind", kind)
	return fmt.Errorf("URL resolves to a non-public address")
}
