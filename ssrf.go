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
	"time"
)

// safeDialContext is used as http.Transport.DialContext for the fetchClient.
// It resolves the hostname itself and rejects any address that is not a
// globally routable unicast IP — see assertPublicIP for the full block list
// — *at TCP-dial time*.
//
// Placing the check here (rather than in a pre-flight before http.Client.Do)
// closes the DNS-rebinding window: an attacker cannot swap the DNS answer
// between our check and the actual TCP connection.
func safeDialContext(ctx context.Context, network, addr string) (net.Conn, error) {
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

	for _, ia := range addrs {
		if err := assertPublicIP(ia.IP); err != nil {
			return nil, err
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
func safeCheckRedirect(req *http.Request, via []*http.Request) error {
	if len(via) >= 5 {
		return fmt.Errorf("stopped after 5 redirects")
	}
	host := req.URL.Hostname()
	addrs, err := net.DefaultResolver.LookupIPAddr(req.Context(), host)
	if err != nil {
		return fmt.Errorf("failed to resolve redirect host: %w", err)
	}
	for _, ia := range addrs {
		if err := assertPublicIP(ia.IP); err != nil {
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
