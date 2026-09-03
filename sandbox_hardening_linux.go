//go:build linux

package main

// sandbox_hardening_linux.go — Linux-specific hardening applied inside the
// extraction child before it reads any attacker-controlled bytes.
//
// This is stage B1: process-level resource bounds and die-with-parent. The
// seccomp-bpf syscall allowlist (B2) will be installed from hardenExtractChild
// once its policy has been developed empirically against the extractor corpus
// (pdf_oxide's ONNX/rayon threading makes the required syscall set something to
// measure, not guess).

import (
	"log/slog"
	"syscall"

	"golang.org/x/sys/unix"
)

// hardenExtractChild drops resource limits for the extraction subprocess.
//
// Deliberately conservative, and deliberately NOT the whole containment story —
// the load-bearing bounds are elsewhere: the parent's wall-clock deadline and
// SIGKILL, the scrubbed environment (no secrets), the absence of any socket (no
// network), and the container's own cgroup memory limit. These limits add
// cheap, safe belt-and-braces on top of that.
//
// Two rlimits that look obvious are intentionally omitted:
//   - RLIMIT_AS (virtual address space): a Go runtime reserves large virtual
//     arenas up front, so an AS cap low enough to matter would kill the child
//     at startup rather than bounding the parser. Memory blowup from a
//     decompression bomb is bounded by the container cgroup and the deadline
//     instead.
//   - RLIMIT_FSIZE=0: pdf_oxide's system-fonts/OCR path may write a fontconfig
//     or model cache; a hard zero would break legitimate extraction. The child
//     has no secrets to exfiltrate to a file anyway.
func hardenExtractChild() {
	// No core dumps: a crashing parser must not spill a core file that embeds
	// the (attacker-controlled) document bytes onto disk.
	setRlimit(unix.RLIMIT_CORE, 0, "RLIMIT_CORE")
	// CPU-time ceiling: bounds a parser stuck in a CPU spin even if something
	// were to defeat the parent's wall-clock kill. Generous (2× the default
	// extraction timeout) so the parent's deadline remains the primary bound.
	setRlimit(unix.RLIMIT_CPU, 120, "RLIMIT_CPU")
}

// setRlimit sets a (soft=hard) resource limit, logging at debug on failure
// rather than aborting: a failed hardening step should degrade the child's
// isolation, not fail the extraction outright (the parent's kill still applies).
func setRlimit(resource int, value uint64, name string) {
	lim := unix.Rlimit{Cur: value, Max: value}
	if err := unix.Setrlimit(resource, &lim); err != nil {
		slog.Debug("sandbox: setrlimit failed", "limit", name, "value", value, "error", err)
	}
}

// extractChildSysProcAttr configures the child process attributes the parent
// sets at spawn time: its own process group (so the parent can signal the whole
// group) and Pdeathsig so the kernel SIGKILLs the child if the parent dies
// before it does — no orphaned extractor can outlive the server.
func extractChildSysProcAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{
		Setpgid:   true,
		Pdeathsig: syscall.SIGKILL,
	}
}
