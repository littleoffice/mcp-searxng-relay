package main

// sandbox.go — process isolation for native document extraction.
//
// pdf_oxide and office_oxide parse attacker-controlled documents through a cgo
// FFI into Rust. Rust is memory-safe in its safe subset, but the FFI boundary,
// any `unsafe` block, and plain logic bugs are all still reachable by a
// malicious PDF/DOCX — and the extractor runs in the same address space as the
// auth-token table, the fence signing key, and every caller's cached content.
// A parser bug there is an RCE-class exposure against all of that.
//
// This moves extraction into a short-lived child process (a re-exec of this
// same binary — the "binary is its own helper" pattern already used by
// --healthcheck). The child holds no secrets (its environment is scrubbed),
// opens no sockets (no network), runs under resource limits, and is killed on a
// deadline. A crash, OOM, or exploit in the parser is therefore contained: the
// parent observes a failed child and returns an ordinary extraction error while
// the server keeps running.
//
// Building the native cores from source (see the Dockerfile) addresses *what
// code is trusted*; this addresses *what a bug in that code can reach*. The two
// are independent halves of the same finding.

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"time"
)

// extractArgMarker is the first argv element of a sandbox child invocation.
// main() dispatches on it before loading any config, exactly like --healthcheck.
const extractArgMarker = "--extract"

// defaultExtractTimeout bounds a single sandboxed extraction. Generous enough
// for a large multi-hundred-page PDF, tight enough that a pathological document
// cannot pin a core indefinitely. Overridable via EXTRACT_TIMEOUT.
const defaultExtractTimeout = 60 * time.Second

// childCrashKind is a test-only fault-injection value for the child's -kind
// flag. It makes the child exit non-zero WITHOUT writing a result, so the
// containment path (parent observes a killed child, returns an error, stays
// alive) can be exercised deterministically. The parent never requests it in
// production, and an attacker does not control this process's argv, so it is
// not an attack surface.
const childCrashKind = "__test_crash"

// extractResult is the framed result a sandbox child writes to stdout. It is
// the union of what extractPDF and extractOffice return; Err carries an
// extractor-level error (a corrupt document), which is distinct from the child
// being killed (reported by the parent as a process failure).
type extractResult struct {
	Text      string `json:"text"`
	Truncated bool   `json:"truncated"`
	PageCount int    `json:"page_count,omitempty"`
	Err       string `json:"error,omitempty"`
}

// isExtractChildInvocation reports whether this process was spawned as a
// sandbox extraction child. Checked in main() (and in tests' TestMain) before
// any configuration is loaded.
func isExtractChildInvocation(args []string) bool {
	return len(args) > 1 && args[1] == extractArgMarker
}

// runExtractChild is the entry point for the sandboxed extraction subprocess.
// It hardens the process BEFORE touching any attacker-controlled bytes, reads
// the document from stdin, runs the requested extractor, writes a framed JSON
// result to stdout, and exits. It never returns.
//
// argv is os.Args[2:] (everything after the extractArgMarker).
func runExtractChild(argv []string) {
	// Harden first: drop resource limits (and, on Linux with the build tag, a
	// seccomp syscall filter) while the process still holds nothing dangerous.
	hardenExtractChild()

	fs := flag.NewFlagSet("extract", flag.ExitOnError)
	kind := fs.String("kind", "", "extractor: pdf or office")
	officeFmt := fs.String("office-format", "", "office format (docx/xlsx/pptx/doc/xls/ppt)")
	maxChars := fs.Int("max-chars", 0, "extraction character cap")
	_ = fs.Parse(argv)

	if *kind == childCrashKind {
		// Test-only: simulate a parser that took the process down.
		os.Exit(3)
	}

	body, err := io.ReadAll(os.Stdin)
	if err != nil {
		writeChildResult(extractResult{Err: "read stdin: " + err.Error()})
		os.Exit(0)
	}

	res := runExtractInProcess(*kind, *officeFmt, body, *maxChars)
	writeChildResult(res)
	os.Exit(0)
}

// runExtractInProcess runs the requested extractor directly in the current
// process. It is the child's worker, and also the parent's fallback when the
// sandbox is disabled (EXTRACT_SANDBOX=false) — the same code path in both, so
// the two modes cannot diverge in output.
func runExtractInProcess(kind, officeFmt string, body []byte, maxChars int) extractResult {
	switch kind {
	case "pdf":
		text, truncated, pageCount, err := extractPDF(body, maxChars)
		r := extractResult{Text: text, Truncated: truncated, PageCount: pageCount}
		if err != nil {
			r.Err = err.Error()
		}
		return r
	case "office":
		text, truncated, err := extractOffice(body, officeFmt, maxChars)
		r := extractResult{Text: text, Truncated: truncated}
		if err != nil {
			r.Err = err.Error()
		}
		return r
	default:
		return extractResult{Err: "unknown extract kind: " + kind}
	}
}

// writeChildResult marshals r to stdout. A marshal error here is a bug rather
// than an operational condition, but the parent must never hang waiting on a
// well-formed frame, so a minimal error object is emitted as a last resort.
func writeChildResult(r extractResult) {
	b, err := json.Marshal(r)
	if err != nil {
		_, _ = io.WriteString(os.Stdout, `{"error":"sandbox child failed to marshal result"}`)
		return
	}
	_, _ = os.Stdout.Write(b)
}

// runSandboxedExtractor runs PDF/Office extraction and returns its result. When
// the sandbox is enabled (the default) it re-execs this binary as a locked-down
// child; otherwise it runs in-process. Both paths return the same shape, with
// an extractor-level error (a corrupt document) surfaced as a non-nil error so
// callers handle it exactly as they did the direct extractPDF/extractOffice
// call this replaces.
//
// A child that is killed, times out, crashes, or returns unparseable output is
// reported as a contained failure: an error to the caller, a metric bump, and
// an intact server process.
func (s *Server) runSandboxedExtractor(ctx context.Context, kind, officeFmt string, body []byte, maxChars int) (extractResult, error) {
	if !s.config.ExtractSandbox {
		res := runExtractInProcess(kind, officeFmt, body, maxChars)
		return resultOrError(kind, res)
	}

	exe, err := os.Executable()
	if err != nil {
		s.metrics.SandboxSpawnErrors.Add(1)
		return extractResult{}, fmt.Errorf("sandbox: cannot locate own executable: %w", err)
	}

	timeout := s.config.ExtractTimeout
	if timeout <= 0 {
		timeout = defaultExtractTimeout
	}
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	argv := []string{extractArgMarker, "-kind=" + kind, fmt.Sprintf("-max-chars=%d", maxChars)}
	if kind == "office" {
		argv = append(argv, "-office-format="+officeFmt)
	}

	cmd := exec.CommandContext(cctx, exe, argv...)
	cmd.Stdin = bytes.NewReader(body)
	var out, errBuf bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errBuf
	// Scrub the environment: the child dispatches on argv before any config is
	// read, so it needs nothing — and must not inherit MCP_*/AUTH_*/FENCE_*/
	// SEARXNG_* secrets it has no use for.
	cmd.Env = []string{}
	// Own process group + die-with-parent (Linux), so a hung child cannot
	// outlive the request or the server.
	cmd.SysProcAttr = extractChildSysProcAttr()
	// After the context kills the child, stop waiting on inherited fds.
	cmd.WaitDelay = 5 * time.Second

	runErr := cmd.Run()

	if cctx.Err() == context.DeadlineExceeded {
		s.metrics.SandboxTimeouts.Add(1)
		return extractResult{}, fmt.Errorf("sandboxed %s extraction timed out after %s (contained)", kind, timeout)
	}
	if runErr != nil {
		s.metrics.SandboxKills.Add(1)
		return extractResult{}, fmt.Errorf("sandboxed %s extraction failed and was contained: %w", kind, runErr)
	}

	var res extractResult
	if err := json.Unmarshal(out.Bytes(), &res); err != nil {
		s.metrics.SandboxKills.Add(1)
		return extractResult{}, fmt.Errorf("sandboxed %s extraction produced unreadable output (contained): %w", kind, err)
	}
	return resultOrError(kind, res)
}

// resultOrError converts an extractor-level Err field into a returned error, so
// the in-process and sandboxed paths present corrupt-document failures
// identically to callers.
func resultOrError(kind string, res extractResult) (extractResult, error) {
	if res.Err != "" {
		return res, fmt.Errorf("%s extraction failed: %s", kind, res.Err)
	}
	return res, nil
}
