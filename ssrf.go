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
	allowedHosts map[string]struct{} // lower-cased, trailing-dot-stripped exact matches
	allowedCIDRs []*net.IPNet
}

// newFetchACL compiles the operator-supplied host and CIDR allow-lists.
// Hostnames are normalised (trimmed, lower-cased, trailing FQDN dot removed).
// Every CIDR must parse; a malformed entry returns an error so startup fails
// loudly rather than silently leaving a range unconfigured — a typo in a
// security control should stop the server, not degrade it quietly.
func newFetchACL(hosts, cidrs []string) (*fetchACL, error) {
	a := &fetchACL{allowedHosts: make(map[string]struct{}, len(hosts))}
	for _, h := range hosts {
		if h = normaliseHost(h); h != "" {
			a.allowedHosts[h] = struct{}{}
		}
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
	return &fetchACL{allowedHosts: map[string]struct{}{}}
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

// hostAllowed reports whether host was explicitly allow-listed by the operator.
func (a *fetchACL) hostAllowed(host string) bool {
	if len(a.allowedHosts) == 0 {
		return false
	}
	_, ok := a.allowedHosts[normaliseHost(host)]
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
	if a.hostAllowed(host) {
		slog.Debug("SSRF: host on allow-list, skipping public-IP check", "host", host)
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
	host := req.URL.Hostname()
	// Same allow-list semantics as the dialer: a redirect *to* an
	// allow-listed host is permitted regardless of the IP it resolves to,
	// while every other host is re-validated per resolved IP so an open
	// redirect on a public host still cannot pivot to a blocked internal one.
	if a.hostAllowed(host) {
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
