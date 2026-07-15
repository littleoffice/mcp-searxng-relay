package main

import (
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

// The histogram is hand-rolled (no client_golang, by supply-chain design),
// so the Prometheus text-format contract is ours to uphold: cumulative
// buckets, le="+Inf" present, and +Inf exactly equal to _count.  Prometheus
// silently miscomputes histogram_quantile when these are violated, which is
// worse than an error — so they are pinned here.

func TestHistogramBucketing(t *testing.T) {
	var h histogram
	h.Observe(10 * time.Millisecond)  // <= 0.05 → bucket 0
	h.Observe(60 * time.Millisecond)  // <= 0.1  → bucket 1
	h.Observe(20 * time.Second)       // <= 30   → last bucket
	h.Observe(45 * time.Second)       // > 30    → overflow (+Inf only)

	if got := h.buckets[0].Load(); got != 1 {
		t.Errorf("bucket le=0.05: got %d, want 1", got)
	}
	if got := h.buckets[1].Load(); got != 1 {
		t.Errorf("bucket le=0.1: got %d, want 1", got)
	}
	if got := h.buckets[len(latencyBuckets)-1].Load(); got != 1 {
		t.Errorf("bucket le=30: got %d, want 1", got)
	}
	if got := h.overflow.Load(); got != 1 {
		t.Errorf("overflow: got %d, want 1", got)
	}
	if got := h.count.Load(); got != 4 {
		t.Errorf("count: got %d, want 4", got)
	}
	wantSum := int64(10*time.Millisecond + 60*time.Millisecond + 20*time.Second + 45*time.Second)
	if got := h.sumNanos.Load(); got != wantSum {
		t.Errorf("sumNanos: got %d, want %d", got, wantSum)
	}
}

func TestHistogramExposition(t *testing.T) {
	var h histogram
	h.Observe(10 * time.Millisecond)
	h.Observe(200 * time.Millisecond) // <= 0.25
	h.Observe(45 * time.Second)       // overflow

	var sb strings.Builder
	h.write(&sb, "test_seconds", "Test histogram.")
	out := sb.String()

	// Buckets must be cumulative: le=0.05 sees 1, le=0.25 sees 2, and
	// every bucket from there through le=30 also sees 2.
	for _, want := range []string{
		"# TYPE test_seconds histogram\n",
		`test_seconds_bucket{le="0.05"} 1` + "\n",
		`test_seconds_bucket{le="0.1"} 1` + "\n",
		`test_seconds_bucket{le="0.25"} 2` + "\n",
		`test_seconds_bucket{le="30"} 2` + "\n",
		`test_seconds_bucket{le="+Inf"} 3` + "\n",
		"test_seconds_count 3\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("exposition missing %q in:\n%s", want, out)
		}
	}

	// _sum is emitted in seconds as a float.
	if !strings.Contains(out, "test_seconds_sum 45.21\n") {
		t.Errorf("exposition sum wrong in:\n%s", out)
	}
}

// The +Inf bucket must equal _count even while observations are landing
// concurrently with exposition.  Both values are derived from the same
// cumulative walk in write(), so the invariant holds by construction —
// this test guards against a refactor that loads them independently.
// Run with -race for full value.
func TestHistogramInfEqualsCountUnderConcurrency(t *testing.T) {
	var h histogram
	stop := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					h.Observe(3 * time.Millisecond)
					h.Observe(40 * time.Second)
				}
			}
		}()
	}

	for i := 0; i < 200; i++ {
		var sb strings.Builder
		h.write(&sb, "t", "t")
		out := sb.String()
		var inf, count int64
		for _, line := range strings.Split(out, "\n") {
			if strings.HasPrefix(line, `t_bucket{le="+Inf"} `) {
				_, _ = fmt.Sscanf(line, `t_bucket{le="+Inf"} %d`, &inf)
			}
			if strings.HasPrefix(line, "t_count ") {
				_, _ = fmt.Sscanf(line, "t_count %d", &count)
			}
		}
		if inf != count {
			close(stop)
			wg.Wait()
			t.Fatalf("iteration %d: +Inf bucket %d != count %d", i, inf, count)
		}
	}
	close(stop)
	wg.Wait()
}
