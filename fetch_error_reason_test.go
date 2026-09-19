package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"syscall"
	"testing"
	"time"
)

// classifyFetchError decides a Prometheus label, so the cases that matter are
// the ones where a wrong answer is plausible: causes that nest inside each
// other, and errors that satisfy more than one test.

func TestClassifyFetchError_Reasons(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want string
	}{
		{"nil", nil, ""},
		{"unclassified", errors.New("something new"), "other"},

		{"invalid url", fmt.Errorf("%w: %w", errInvalidURL, errors.New("bad")), "invalid_url"},
		{"scheme", fmt.Errorf("%w: only http/https", errSchemeRejected), "scheme_rejected"},
		{"status", fmt.Errorf("%w: URL returned HTTP 404", errHTTPStatus), "http_status"},
		{"extraction", fmt.Errorf("%w: PDF text: %w", errExtractFailed, errors.New("corrupt")), "extract_failed"},

		// Wrapped the way the transport actually returns them.
		{"ssrf", fmt.Errorf("failed to fetch URL: %w", &blockedAddrError{reason: "loopback"}), "ssrf_blocked"},
		{"dns", fmt.Errorf("failed to fetch URL: %w", &net.DNSError{Err: "no such host", Name: "nope.invalid"}), "dns"},
		{"deadline", fmt.Errorf("failed to fetch URL: %w", context.DeadlineExceeded), "timeout"},
		{"refused", fmt.Errorf("failed to fetch URL: %w", syscall.ECONNREFUSED), "refused"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := classifyFetchError(tc.err); got != tc.want {
				t.Errorf("classifyFetchError(%v) = %q, want %q", tc.err, got, tc.want)
			}
		})
	}
}

// A resolver that gave up waiting is both a DNS error and a timeout. "the
// name did not resolve" is the more actionable of the two, and the ordering
// in classifyFetchError exists to guarantee it wins.
func TestClassifyFetchError_DNSTimeoutPrefersDNS(t *testing.T) {
	err := fmt.Errorf("failed to fetch URL: %w",
		&net.DNSError{Err: "i/o timeout", Name: "slow.invalid", IsTimeout: true})

	if got := classifyFetchError(err); got != "dns" {
		t.Errorf("classifyFetchError = %q, want %q — a resolver timeout is a DNS failure first", got, "dns")
	}
}

// An SSRF refusal surfaces through the dialer, so it arrives wrapped in a
// transport error and would answer to a generic network check too. It must
// still be reported as the refusal it is, or the guardrail becomes invisible
// on the dashboard exactly when it fires.
func TestClassifyFetchError_SSRFBeatsGenericNetworkError(t *testing.T) {
	var netErr net.Error = &net.OpError{
		Op:  "dial",
		Err: &blockedAddrError{reason: "private"},
	}
	if got := classifyFetchError(fmt.Errorf("failed to fetch URL: %w", netErr)); got != "ssrf_blocked" {
		t.Errorf("classifyFetchError = %q, want %q", got, "ssrf_blocked")
	}
}

func TestRecordFetchError_CountsUnderReason(t *testing.T) {
	var m Metrics
	m.recordFetchError(fmt.Errorf("%w: URL returned HTTP 500", errHTTPStatus))
	m.recordFetchError(fmt.Errorf("%w: URL returned HTTP 404", errHTTPStatus))
	m.recordFetchError(errors.New("never seen before"))

	if got := reasonCount(&m, "http_status"); got != 2 {
		t.Errorf("http_status = %d, want 2", got)
	}
	if got := reasonCount(&m, "other"); got != 1 {
		t.Errorf("other = %d, want 1", got)
	}
	if got := reasonCount(&m, "timeout"); got != 0 {
		t.Errorf("timeout = %d, want 0", got)
	}
}

func reasonCount(m *Metrics, reason string) int64 {
	for i, r := range fetchErrorReasons {
		if r == reason {
			return m.FetchErrorsByReason[i].Load()
		}
	}
	return -1
}

func TestFetchErrorsByReason_Exposed(t *testing.T) {
	s := NewServer(Config{CacheMaxEntries: 1})
	s.metrics.recordFetchError(fmt.Errorf("%w: bad", errInvalidURL))

	rec := httptest.NewRecorder()
	s.ServeMetrics(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	body := rec.Body.String()

	for _, want := range []string{
		"# TYPE mcp_fetch_errors_by_reason_total counter\n",
		`mcp_fetch_errors_by_reason_total{reason="invalid_url"} 1` + "\n",
		// Zero series still emitted, so increase() has a baseline.
		`mcp_fetch_errors_by_reason_total{reason="timeout"} 0` + "\n",
		`mcp_fetch_errors_by_reason_total{reason="other"} 0` + "\n",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("metrics output missing %q", want)
		}
	}

	// The pre-existing unlabelled counter must survive: it is what the
	// dashboard and any existing alert already query.
	if !strings.Contains(body, "# TYPE mcp_fetch_errors_total counter\n") {
		t.Error("mcp_fetch_errors_total disappeared; the by-reason counter is meant to be additive")
	}
}

// End to end through the tool handler: a real failure must land in the
// by-reason counter and name its cause on the log line.
func TestToolReadURL_FailureRecordsReason(t *testing.T) {
	s := NewServer(Config{CacheMaxEntries: 8, CacheTTL: time.Minute})

	recs := captureRecords(t, func() {
		_, _, _ = s.toolReadURL(context.Background(), nil, fetchInput{URL: "ftp://example.org/x"})
	})

	if got := reasonCount(&s.metrics, "scheme_rejected"); got != 1 {
		t.Errorf("scheme_rejected = %d, want 1", got)
	}
	if got := s.metrics.FetchErrors.Load(); got != 1 {
		t.Errorf("mcp_fetch_errors_total = %d, want 1 — the unlabelled counter still counts", got)
	}

	rec := findRecord(t, recs, "fetch failed")
	if got := rec["reason"]; got != "scheme_rejected" {
		t.Errorf("log reason = %v, want %q", got, "scheme_rejected")
	}
	if got := rec["tool"]; got != "searxng_read_url" {
		t.Errorf("log tool = %v, want %q", got, "searxng_read_url")
	}
}
