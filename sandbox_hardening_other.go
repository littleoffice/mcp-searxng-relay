//go:build !linux

package main

// sandbox_hardening_other.go — no-op hardening for non-Linux platforms.
//
// The production target is a Linux scratch container, where
// sandbox_hardening_linux.go applies rlimits and die-with-parent. This file
// keeps the package building (and the subprocess sandbox functional, minus the
// Linux-only bounds) on macOS/other for local development and tests: the child
// still runs as a separate, secret-free, network-free process killed on a
// deadline — the core of the containment — it just lacks the Linux rlimits and
// the seccomp filter that land under the linux build tag.

import "syscall"

// hardenExtractChild is a no-op on non-Linux platforms.
func hardenExtractChild() {}

// extractChildSysProcAttr returns nil on non-Linux platforms: Pdeathsig is a
// Linux-only field, and the SysProcAttr shape varies across the other targets,
// so the safe portable default is to set nothing.
func extractChildSysProcAttr() *syscall.SysProcAttr { return nil }
