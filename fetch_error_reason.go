package main

import (
	"context"
	"errors"
	"net"
	"syscall"
)

// Failure-cause classification for the fetch pipeline.
//
// mcp_fetch_errors_total records that a fetch failed and nothing about why,
// so a rate that moves tells an operator to go read logs. A timeout against a
// slow origin, a 404 the model invented, an SSRF refusal and a corrupt PDF
// are four different incidents with four different responses, and collapsing
// them into one line on a dashboard hides which one is happening.
//
// The reason set is deliberately closed and small: it is a Prometheus label,
// so an open set (an error string, a status code) would be unbounded
// cardinality driven by attacker-controlled input — a fetched page decides
// its own status code.
//
// Classification is by error identity, not by matching message text: the
// relay tags its own failures with the sentinels below and the transport's
// failures are inspected through errors.As/errors.Is. Message matching would
// silently reclassify every error the moment someone rewords a string.
var (
	// errInvalidURL covers a URL the parser rejected outright.
	errInvalidURL = errors.New("invalid URL")
	// errSchemeRejected is a well-formed URL the relay will not dial,
	// i.e. anything that is not http or https.
	errSchemeRejected = errors.New("unsupported URL scheme")
	// errHTTPStatus is a completed round-trip that returned a non-2xx
	// status. The status itself stays in the message and the log line; only
	// the fact of it reaches the metric.
	errHTTPStatus = errors.New("upstream returned a non-success status")
	// errExtractFailed is a document the relay fetched but could not turn
	// into text — a corrupt PDF, an Office file it cannot parse.
	errExtractFailed = errors.New("content extraction failed")
)

// fetchErrorReasons is the closed label set for
// mcp_fetch_errors_by_reason_total. "other" is the catch-all and is worth
// alerting on in its own right: a rising "other" means a failure mode nobody
// has classified yet.
var fetchErrorReasons = [...]string{
	"invalid_url",
	"scheme_rejected",
	"ssrf_blocked",
	"dns",
	"timeout",
	"refused",
	"http_status",
	"extract_failed",
	"other",
}

// classifyFetchError maps a readURL failure onto one of fetchErrorReasons.
//
// Order matters where causes nest. A blocked address surfaces through the
// dialer and so arrives wrapped in the transport's error, which would also
// satisfy a naive "did the dial fail" check — so the SSRF case is tested
// before the generic network ones. Likewise a DNS failure carries a timeout
// flag when the resolver itself timed out, and "the name did not resolve" is
// the more useful of the two, so it is tested first.
func classifyFetchError(err error) string {
	if err == nil {
		return ""
	}

	switch {
	case errors.Is(err, errInvalidURL):
		return "invalid_url"
	case errors.Is(err, errSchemeRejected):
		return "scheme_rejected"
	case errors.Is(err, errHTTPStatus):
		return "http_status"
	case errors.Is(err, errExtractFailed):
		return "extract_failed"
	}

	// The relay's own refusal to dial a non-public address, which reaches
	// here wrapped in whatever the transport returned around it.
	var blocked *blockedAddrError
	if errors.As(err, &blocked) {
		return "ssrf_blocked"
	}

	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return "dns"
	}

	// context.DeadlineExceeded covers the per-request timeout; net.Error's
	// Timeout() covers deadlines the transport applied itself.
	if errors.Is(err, context.DeadlineExceeded) {
		return "timeout"
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return "timeout"
	}

	if errors.Is(err, syscall.ECONNREFUSED) {
		return "refused"
	}

	return "other"
}
