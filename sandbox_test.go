package main

import (
	"context"
	"os"
	"strings"
	"testing"
)

// TestMain lets the test binary act as its own sandbox extraction child. When
// runSandboxedExtractor re-execs os.Executable() during a test, that executable
// IS this test binary, so it must recognise the --extract marker and dispatch
// to runExtractChild before the testing framework takes over — exactly as
// main() does in production. Without this the re-exec would run the test suite
// instead of the extractor.
func TestMain(m *testing.M) {
	if isExtractChildInvocation(os.Args) {
		runExtractChild(os.Args[2:])
		return // unreachable — runExtractChild calls os.Exit
	}
	os.Exit(m.Run())
}

// sandboxTestServer builds a minimal Server carrying only the config the
// sandbox path reads. No cache, no MCP server, no history — runSandboxedExtractor
// touches only s.config and s.metrics.
func sandboxTestServer(enabled bool) *Server {
	return &Server{config: Config{ExtractSandbox: enabled}}
}

// A parser that crashes the process must be contained: the child dies, the
// parent reports a contained error and bumps the kill metric, and — the point
// of the whole exercise — the parent process is still alive to serve the next
// request. Uses the test-only crash kind so the failure is deterministic rather
// than relying on finding an input that happens to segfault the real parser.
func TestSandbox_ContainedCrash(t *testing.T) {
	s := sandboxTestServer(true)

	_, err := s.runSandboxedExtractor(context.Background(), childCrashKind, "", []byte("irrelevant"), 1000)
	if err == nil {
		t.Fatal("expected a contained error when the child crashes, got nil")
	}
	if got := s.metrics.SandboxKills.Load(); got != 1 {
		t.Errorf("SandboxKills = %d, want 1", got)
	}
	// The parent is obviously still running (this test is executing), but assert
	// it can immediately run another extraction — a crashed child must not have
	// poisoned any shared state.
	if _, err := s.runSandboxedExtractor(context.Background(), "pdf", "", []byte("%PDF-not-real"), 1000); err == nil {
		t.Error("expected malformed-PDF error on the follow-up call, got nil")
	}
}

// A malformed document must surface as an ordinary extraction error through the
// real subprocess round-trip (spawn child -> harden -> read stdin -> run the
// real cgo extractor -> frame the error -> parent unmarshals -> returns error),
// with the server intact.
func TestSandbox_MalformedPDFContained(t *testing.T) {
	s := sandboxTestServer(true)

	_, err := s.runSandboxedExtractor(context.Background(), "pdf", "", []byte("this is not a pdf"), 1000)
	if err == nil {
		t.Fatal("expected an extraction error for a non-PDF body, got nil")
	}
	// This is an extractor-level error carried in the child's result frame, not
	// a killed child, so the kill counter must NOT move.
	if got := s.metrics.SandboxKills.Load(); got != 0 {
		t.Errorf("SandboxKills = %d, want 0 (extractor error is not a kill)", got)
	}
}

func TestSandbox_MalformedOfficeContained(t *testing.T) {
	s := sandboxTestServer(true)

	_, err := s.runSandboxedExtractor(context.Background(), "office", "docx", []byte("PK-not-a-real-docx"), 1000)
	if err == nil {
		t.Fatal("expected an extraction error for a non-DOCX body, got nil")
	}
}

// The in-process fallback (EXTRACT_SANDBOX=false) must present the same
// malformed-input behaviour as the sandboxed path: an error, no subprocess, no
// kill metric.
func TestSandbox_DisabledInProcessParity(t *testing.T) {
	s := sandboxTestServer(false)

	_, err := s.runSandboxedExtractor(context.Background(), "pdf", "", []byte("this is not a pdf"), 1000)
	if err == nil {
		t.Fatal("expected an extraction error in-process, got nil")
	}
	if got := s.metrics.SandboxKills.Load(); got != 0 {
		t.Errorf("SandboxKills = %d, want 0 (no subprocess in disabled mode)", got)
	}
	if got := s.metrics.SandboxSpawnErrors.Load(); got != 0 {
		t.Errorf("SandboxSpawnErrors = %d, want 0", got)
	}
}

// An unknown extractor kind is reported as an error rather than silently
// returning empty text, in both modes.
func TestSandbox_UnknownKind(t *testing.T) {
	for _, enabled := range []bool{true, false} {
		s := sandboxTestServer(enabled)
		_, err := s.runSandboxedExtractor(context.Background(), "tiff", "", []byte("x"), 100)
		if err == nil || !strings.Contains(err.Error(), "unknown extract kind") {
			t.Errorf("sandbox=%v: want an 'unknown extract kind' error, got %v", enabled, err)
		}
	}
}

func TestConfigFromEnv_ExtractSandboxDefaults(t *testing.T) {
	t.Setenv("SEARXNG_URL", "http://searxng.invalid")
	cfg := configFromEnv()
	if !cfg.ExtractSandbox {
		t.Error("ExtractSandbox should default to true")
	}
	if cfg.ExtractTimeout != defaultExtractTimeout {
		t.Errorf("ExtractTimeout = %s, want default %s", cfg.ExtractTimeout, defaultExtractTimeout)
	}

	t.Setenv("EXTRACT_SANDBOX", "false")
	t.Setenv("EXTRACT_TIMEOUT", "30s")
	cfg = configFromEnv()
	if cfg.ExtractSandbox {
		t.Error("EXTRACT_SANDBOX=false should disable the sandbox")
	}
	if cfg.ExtractTimeout.String() != "30s" {
		t.Errorf("ExtractTimeout = %s, want 30s", cfg.ExtractTimeout)
	}
}
