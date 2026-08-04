package main

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"testing"
)

// Caller attribution is the join key for audit forensics: a log line saying
// a URL was fetched is close to useless if it does not also say on whose
// behalf.  These tests pin the two properties that make the join reliable —
// the attrs survive context propagation into the shared fetch pipeline, and
// the key set is stable even when there is nothing to attribute.

// captureLog swaps in a JSON handler over a buffer for the duration of fn,
// then decodes the single record written.
func captureLog(t *testing.T, fn func()) map[string]any {
	t.Helper()

	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	})))
	defer slog.SetDefault(prev)

	fn()

	var rec map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &rec); err != nil {
		t.Fatalf("decoding log record: %v (raw: %q)", err, buf.String())
	}
	return rec
}

func TestCallerLoggerEmitsAttribution(t *testing.T) {
	ctx := withSessionID(withIdentity(context.Background(), "alice"), "sess-123")

	rec := captureLog(t, func() {
		callerLogger(ctx).Info("url fetched", "url", "https://example.com")
	})

	if got := rec["identity"]; got != "alice" {
		t.Errorf("identity = %v, want %q", got, "alice")
	}
	if got := rec["session_id"]; got != "sess-123" {
		t.Errorf("session_id = %v, want %q", got, "sess-123")
	}
	if got := rec["url"]; got != "https://example.com" {
		t.Errorf("url = %v, want %q", got, "https://example.com")
	}
}

// Absent attribution must still emit both keys, empty.  Log processors key
// off a stable schema; omitting the fields in stdio mode would mean an
// alert on "unattributed fetch" could not distinguish "no identity" from
// "field dropped by a code path that forgot to log it".
func TestCallerLoggerKeysAlwaysPresent(t *testing.T) {
	rec := captureLog(t, func() {
		callerLogger(context.Background()).Info("url fetched")
	})

	for _, key := range []string{"identity", "session_id"} {
		got, ok := rec[key]
		if !ok {
			t.Errorf("%s key missing entirely", key)
			continue
		}
		if got != "" {
			t.Errorf("%s = %v, want empty string", key, got)
		}
	}
}

// The shared readURL pipeline serves both searxng_read_url and
// searxng_url_metadata and never sees a CallToolRequest, so it depends
// entirely on the tool handlers having bound the session ID into the
// context.  This pins that the value survives a derived context.
func TestSessionIDSurvivesContextDerivation(t *testing.T) {
	ctx := withSessionID(context.Background(), "sess-abc")
	derived, cancel := context.WithCancel(ctx)
	defer cancel()

	if got := sessionIDFromContext(derived); got != "sess-abc" {
		t.Errorf("session_id = %q, want %q", got, "sess-abc")
	}
	if got := sessionIDFromContext(context.Background()); got != "" {
		t.Errorf("session_id on bare context = %q, want empty", got)
	}
}
