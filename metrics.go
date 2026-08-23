package main

import (
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ── Metrics ───────────────────────────────────────────────────────────────────

// maxTrackedDomains caps how many distinct domains are tracked in the
// per-domain fetch counter. Past this threshold, additional domains are
// aggregated into the overflow counter rather than expanding the map. The
// cap protects against cardinality blowup if an agent fetches many unique
// hosts — Prometheus is unhappy with unbounded label sets, and the map
// itself would otherwise grow without bound for the process lifetime.
const maxTrackedDomains = 512

// domainStats holds atomic per-domain success / failure counters.
type domainStats struct {
	successes atomic.Int64
	failures  atomic.Int64
}

// latencyBuckets are the upper bounds (seconds) for the duration histograms.
// Coarse on purpose: these exist for alerting ("upstream is slow"), not for
// profiling.  The top bucket sits at 30s to match the fetch client timeout —
// anything above it lands in +Inf and means a timeout-adjacent request.
// Changing bucket bounds mid-deployment resets the usefulness of historical
// quantile queries, so treat the set as stable.
var latencyBuckets = [...]float64{0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30}

// histogram is a fixed-bucket Prometheus histogram safe for concurrent use
// without a mutex.  Internally each bucket counts only its own range
// (non-cumulative), so Observe touches exactly one bucket counter plus sum
// and count; the cumulative form Prometheus requires is computed at
// exposition time.  The sum is kept in integer nanoseconds rather than a
// CAS-looped float64 — at a 30s per-observation ceiling, int64 nanoseconds
// take centuries of cumulative latency to overflow.
type histogram struct {
	buckets  [len(latencyBuckets)]atomic.Int64
	overflow atomic.Int64 // observations above the last bucket (le="+Inf")
	sumNanos atomic.Int64
	count    atomic.Int64
}

// Observe records one duration.
func (h *histogram) Observe(d time.Duration) {
	secs := d.Seconds()
	placed := false
	for i, ub := range latencyBuckets {
		if secs <= ub {
			h.buckets[i].Add(1)
			placed = true
			break
		}
	}
	if !placed {
		h.overflow.Add(1)
	}
	h.sumNanos.Add(int64(d))
	h.count.Add(1)
}

// write emits the histogram in Prometheus text exposition format.
//
// The le="+Inf" bucket and _count are both computed from the same cumulative
// sum over the bucket counters, which preserves the Prometheus invariant
// (+Inf == _count) even when Observe runs concurrently with exposition.  The
// independently loaded count/sum fields may momentarily lag the buckets by
// an in-flight observation; that skew is bounded to a scrape's instant and
// is the standard trade-off of lock-free collection, so count is derived
// rather than loaded.
func (h *histogram) write(w io.Writer, name, help string) {
	_, _ = fmt.Fprintf(w, "# HELP %s %s\n", name, help)
	_, _ = fmt.Fprintf(w, "# TYPE %s histogram\n", name)
	var cum int64
	for i, ub := range latencyBuckets {
		cum += h.buckets[i].Load()
		_, _ = fmt.Fprintf(w, "%s_bucket{le=\"%g\"} %d\n", name, ub, cum)
	}
	cum += h.overflow.Load()
	_, _ = fmt.Fprintf(w, "%s_bucket{le=\"+Inf\"} %d\n", name, cum)
	_, _ = fmt.Fprintf(w, "%s_sum %g\n", name, float64(h.sumNanos.Load())/1e9)
	_, _ = fmt.Fprintf(w, "%s_count %d\n\n", name, cum)
}

// Metrics holds all in-process counters exposed at /metrics in Prometheus
// text format.  All fields are atomic so they can be incremented from
// concurrent goroutines without a mutex.
type Metrics struct {
	// ── search tool ──────────────────────────────────────────────────────────
	SearchTotal  atomic.Int64 // all calls to searxng_web_search
	SearchErrors atomic.Int64 // calls that returned an error

	// ── fetch tool ───────────────────────────────────────────────────────────
	FetchTotal  atomic.Int64 // all calls to searxng_read_url
	FetchErrors atomic.Int64 // calls that returned an error
	FetchHTML   atomic.Int64 // responses dispatched to the HTML extractor
	FetchPDF    atomic.Int64 // responses dispatched to the PDF extractor
	FetchOffice atomic.Int64 // responses dispatched to the Office extractor (DOCX/XLSX/PPTX + legacy)
	FetchPlain  atomic.Int64 // responses dispatched as text/plain
	FetchImage  atomic.Int64 // responses returned as image content blocks

	// ── per-domain fetch tracking ───────────────────────────────────────────
	// domains is a bounded map of hostname → success/failure counters. The
	// mutex guards map mutations (insert / cap-check); the atomic.Int64s
	// inside domainStats are updated lock-free once the entry exists.
	//
	// Once maxTrackedDomains entries are present, further unique domains
	// roll up into the Overflow counters. This is observability about which
	// domains are misbehaving, not an audit log of every URL fetched —
	// operators who need the latter should rely on the structured fetch
	// log lines (`url=...`) instead.
	domainsMu                sync.RWMutex
	domains                  map[string]*domainStats
	FetchDomainOverflowOK    atomic.Int64
	FetchDomainOverflowError atomic.Int64

	// ── cache ─────────────────────────────────────────────────────────────────
	CacheHits         atomic.Int64 // readURL served from cache
	CacheMisses       atomic.Int64 // readURL triggered a network fetch
	CacheForceRefresh atomic.Int64 // readURL called with force_refresh=true

	// ── metadata tool ────────────────────────────────────────────────────────
	MetadataTotal  atomic.Int64 // all calls to searxng_url_metadata
	MetadataErrors atomic.Int64 // calls that returned an error

	// ── session sources tool ─────────────────────────────────────────────────
	// No error counter: the tool reads in-process state and has no failure
	// mode short of a JSON marshal error, which would be a bug rather than
	// an operational condition.  The ratio of this counter to
	// mcp_fetches_total is the interesting signal — it says how often
	// agents verify their URLs before answering.
	SourcesTotal atomic.Int64 // all calls to searxng_session_sources

	// Whether the per-caller cap (MCP_HISTORY_ENTRIES) is big enough is an
	// empirical question, and these two are how it gets answered instead of
	// guessed.  HistoryEvictions counts sources dropped to make room, which
	// says how far over the cap callers run.  SourcesElided counts the tool
	// calls that came back short, which is the one that matters: it means an
	// agent composed an answer against a list that no longer held everything
	// it had read.  A persistently non-zero SourcesElided is the signal to
	// raise the cap; evictions alone can be noise from one long-running
	// caller that never reads its list back.
	HistoryEvictions atomic.Int64
	SourcesElided    atomic.Int64

	// ── latency ──────────────────────────────────────────────────────────────
	// Duration histograms for the two upstream operations an operator
	// alerts on.  "Upstream is slow" is a more common incident than
	// "upstream is down", and counters alone cannot express it.
	//
	// SearchDuration measures the SearXNG round-trip inside toolSearch.
	// FetchDuration measures the readURL pipeline (dial through
	// extraction) and therefore includes cache hits, which observe as
	// sub-millisecond values in the lowest bucket; alert on upper
	// quantiles, and read the p50 alongside mcp_cache_hits_total.
	SearchDuration histogram
	FetchDuration  histogram

	// ── rate limiting ────────────────────────────────────────────────────────
	// Single counter — no per-identity label.  The rejection event is
	// already logged at WARN with identity / remote / path; the metric
	// exists for dashboards and alerting where unbounded cardinality
	// would be worse than aggregated visibility.
	RateLimitRejections atomic.Int64
}

// recordFetchByDomain bumps the per-domain success or failure counter for the
// given hostname. The first call for a new domain takes the write lock to
// insert the entry; subsequent calls take only the read lock and update the
// atomic counters lock-free. When the domain cap is reached, new domains are
// counted in the overflow bucket instead.
func (m *Metrics) recordFetchByDomain(domain string, ok bool) {
	if domain == "" {
		domain = "unknown"
	}

	// Fast path: entry exists, no write lock needed.
	m.domainsMu.RLock()
	ds, exists := m.domains[domain]
	m.domainsMu.RUnlock()

	if !exists {
		m.domainsMu.Lock()
		// Re-check under the write lock — another goroutine may have inserted.
		ds, exists = m.domains[domain]
		if !exists {
			if len(m.domains) >= maxTrackedDomains {
				m.domainsMu.Unlock()
				if ok {
					m.FetchDomainOverflowOK.Add(1)
				} else {
					m.FetchDomainOverflowError.Add(1)
				}
				return
			}
			if m.domains == nil {
				m.domains = make(map[string]*domainStats, 64)
			}
			ds = &domainStats{}
			m.domains[domain] = ds
		}
		m.domainsMu.Unlock()
	}

	if ok {
		ds.successes.Add(1)
	} else {
		ds.failures.Add(1)
	}
}

// escapePromLabel escapes a Prometheus label value per the text exposition
// format: backslash, double-quote, and newline are the only required escapes.
// Domain names should never contain any of these in practice, but a malformed
// URL could produce odd hostnames, and escaping is cheap insurance against
// breaking the /metrics output.
func escapePromLabel(s string) string {
	if !strings.ContainsAny(s, "\\\"\n") {
		return s
	}
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	s = strings.ReplaceAll(s, "\n", `\n`)
	return s
}

// ServeMetrics writes all counters in Prometheus text exposition format.
// Registered at GET /metrics (behind auth in HTTP mode).
//
// The session gauge is sourced from the SDK's live session set rather than
// a counter we maintain ourselves — the SDK is the source of truth now.
func (s *Server) ServeMetrics(w http.ResponseWriter, _ *http.Request) {
	m := &s.metrics
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	w.WriteHeader(http.StatusOK)

	writeCounter := func(name, help string, v *atomic.Int64) {
		_, _ = fmt.Fprintf(w, "# HELP %s %s\n", name, help)
		_, _ = fmt.Fprintf(w, "# TYPE %s counter\n", name)
		_, _ = fmt.Fprintf(w, "%s %d\n\n", name, v.Load())
	}

	writeGauge := func(name, help string, val int64) {
		_, _ = fmt.Fprintf(w, "# HELP %s %s\n", name, help)
		// TYPE gauge, not counter: the value rises and falls as sessions open
		// and close. Exposing it as a counter makes rate()/increase() treat
		// every decrease as a counter reset and silently corrupts those queries.
		_, _ = fmt.Fprintf(w, "# TYPE %s gauge\n", name)
		_, _ = fmt.Fprintf(w, "%s %d\n\n", name, val)
	}

	// Metadata
	writeCounter("mcp_metadata_total",
		"Total number of searxng_url_metadata tool calls.", &m.MetadataTotal)
	writeCounter("mcp_metadata_errors_total",
		"Total number of searxng_url_metadata calls that returned an error.", &m.MetadataErrors)

	// Session sources
	writeCounter("mcp_session_sources_total",
		"Total number of searxng_session_sources tool calls.", &m.SourcesTotal)
	writeCounter("mcp_session_sources_elided_total",
		"Total number of searxng_session_sources calls that returned an incomplete list.", &m.SourcesElided)
	writeCounter("mcp_history_evictions_total",
		"Total number of sources dropped from a caller's history to make room.", &m.HistoryEvictions)

	// Search
	writeCounter("mcp_searches_total",
		"Total number of searxng_web_search tool calls.", &m.SearchTotal)
	writeCounter("mcp_search_errors_total",
		"Total number of searxng_web_search calls that returned an error.", &m.SearchErrors)

	// Fetch
	writeCounter("mcp_fetches_total",
		"Total number of searxng_read_url tool calls.", &m.FetchTotal)
	writeCounter("mcp_fetch_errors_total",
		"Total number of searxng_read_url calls that returned an error.", &m.FetchErrors)

	// Fetch by content type
	_, _ = fmt.Fprintf(w, "# HELP mcp_fetches_by_type_total Total fetches broken down by content type.\n")
	_, _ = fmt.Fprintf(w, "# TYPE mcp_fetches_by_type_total counter\n")
	_, _ = fmt.Fprintf(w, "mcp_fetches_by_type_total{type=\"html\"} %d\n", m.FetchHTML.Load())
	_, _ = fmt.Fprintf(w, "mcp_fetches_by_type_total{type=\"pdf\"} %d\n", m.FetchPDF.Load())
	_, _ = fmt.Fprintf(w, "mcp_fetches_by_type_total{type=\"office\"} %d\n", m.FetchOffice.Load())
	_, _ = fmt.Fprintf(w, "mcp_fetches_by_type_total{type=\"plain\"} %d\n", m.FetchPlain.Load())
	_, _ = fmt.Fprintf(w, "mcp_fetches_by_type_total{type=\"image\"} %d\n\n", m.FetchImage.Load())

	// Fetch by domain — bounded cardinality (see maxTrackedDomains).
	// Snapshot under the read lock so we don't hold it across the HTTP write.
	type domainSnap struct {
		domain    string
		successes int64
		failures  int64
	}
	m.domainsMu.RLock()
	snaps := make([]domainSnap, 0, len(m.domains))
	for d, ds := range m.domains {
		snaps = append(snaps, domainSnap{
			domain:    d,
			successes: ds.successes.Load(),
			failures:  ds.failures.Load(),
		})
	}
	m.domainsMu.RUnlock()
	sort.Slice(snaps, func(i, j int) bool { return snaps[i].domain < snaps[j].domain })

	_, _ = fmt.Fprintf(w, "# HELP mcp_fetches_by_domain_total Fetches broken down by destination domain and outcome.\n")
	_, _ = fmt.Fprintf(w, "# TYPE mcp_fetches_by_domain_total counter\n")
	for _, snap := range snaps {
		esc := escapePromLabel(snap.domain)
		_, _ = fmt.Fprintf(w, "mcp_fetches_by_domain_total{domain=\"%s\",outcome=\"success\"} %d\n",
			esc, snap.successes)
		_, _ = fmt.Fprintf(w, "mcp_fetches_by_domain_total{domain=\"%s\",outcome=\"error\"} %d\n",
			esc, snap.failures)
	}
	// Overflow bucket — domains beyond the tracked cap aggregate here.
	_, _ = fmt.Fprintf(w, "mcp_fetches_by_domain_total{domain=\"__overflow__\",outcome=\"success\"} %d\n",
		m.FetchDomainOverflowOK.Load())
	_, _ = fmt.Fprintf(w, "mcp_fetches_by_domain_total{domain=\"__overflow__\",outcome=\"error\"} %d\n\n",
		m.FetchDomainOverflowError.Load())

	// Cache
	writeCounter("mcp_cache_hits_total",
		"Total number of URL fetch requests served from the in-memory cache.", &m.CacheHits)
	writeCounter("mcp_cache_misses_total",
		"Total number of URL fetch requests that required a network call.", &m.CacheMisses)
	writeCounter("mcp_cache_force_refresh_total",
		"Total number of URL fetch requests with force_refresh=true.", &m.CacheForceRefresh)

	// Rate limiting
	writeCounter("mcp_rate_limit_rejections_total",
		"Total number of HTTP requests rejected by the per-caller rate limiter.", &m.RateLimitRejections)

	// Latency histograms
	m.SearchDuration.write(w, "mcp_search_duration_seconds",
		"Duration of SearXNG search round-trips, in seconds.")
	m.FetchDuration.write(w, "mcp_fetch_duration_seconds",
		"Duration of the URL fetch pipeline (dial through extraction), in seconds. Includes cache hits, which observe as sub-millisecond values.")

	// Sessions (gauge — current live count, snapshotted from the SDK)
	writeGauge("mcp_active_sessions",
		"Current number of active MCP sessions.", int64(s.sessionCount()))
}
