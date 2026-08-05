package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"
)

// ── Fence signing key persistence ─────────────────────────────────────────────
//
// By default this server generates a fresh Ed25519 fence signing key at every
// process start (see generateFenceKeypair in fence.go).  That default is
// deliberate and is NOT changed by this file: without an external trust
// anchor, a persisted key would imply a continuity property the server cannot
// deliver on its own.
//
// However, a downstream verifier — the "security gateway" of arXiv:2511.19727
// §4.5 — cannot do its job against a key that changes every restart.  Its only
// options are to re-fetch /fence/public-key at verification time (which
// degrades the signature check to "signed by whoever answered", since an
// attacker able to impersonate the relay also serves their own key) or to
// re-pin a fingerprint by hand after every deploy.
//
// So this file adds an opt-in: when the operator supplies a key, we use it and
// say so loudly in the logs; when they don't, behaviour is byte-for-byte what
// it was before.  The trust anchor is thereby moved to where it belongs — the
// operator's KMS, secret store, or mounted file — rather than being invented
// by this process.
//
// Two environment variables, mutually exclusive:
//
//	FENCE_SIGNING_KEY       key material inline
//	FENCE_SIGNING_KEY_FILE  path to a file holding the same
//
// Accepted encodings (auto-detected, no format flag to get wrong):
//
//	PKCS#8 PEM          `openssl genpkey -algorithm ed25519`
//	PKCS#8 DER, base64  the above, `-outform DER`, base64'd
//	32-byte seed, b64   `openssl rand -base64 32` (any 32 bytes is a valid seed)
//	64-byte key, b64    seed||public, as produced by ed25519.GenerateKey
//
// Key material is never logged, never included in an error message, and never
// placed in the startup banner — only the SHA-256 fingerprint of the derived
// PUBLIC key is displayed, which is the same value operators already use to
// cross-check against /fence/public-key.

const (
	fenceKeyEnvVar     = "FENCE_SIGNING_KEY"
	fenceKeyFileEnvVar = "FENCE_SIGNING_KEY_FILE"
)

// loadFenceSigningKey resolves the operator-supplied fence signing key, if
// any.  It is called from main() before NewServer, matching the fail-loud
// pattern used for the fetch ACL and the auth-token table: a malformed key
// stops startup with an actionable message rather than silently degrading to
// an ephemeral key the operator's gateway will then reject every fence from.
//
// Returns (nil, "", nil) when neither variable is set — the default, and the
// signal to NewServer that it should generate an ephemeral keypair.
//
// The second return value is a short human-readable description of where the
// key came from, for the startup banner and the audit log line.  It never
// contains key material.
func loadFenceSigningKey(inline, path string) (ed25519.PrivateKey, string, error) {
	inline = strings.TrimSpace(inline)
	path = strings.TrimSpace(path)

	switch {
	case inline == "" && path == "":
		// Neither set: preserve the historical ephemeral-key behaviour.
		return nil, "", nil
	case inline != "" && path != "":
		// Refuse to guess.  Silently preferring one would mean an operator
		// rotating via the file could keep signing with a stale inline key
		// and never know.
		return nil, "", fmt.Errorf("%s and %s are both set; configure exactly one",
			fenceKeyEnvVar, fenceKeyFileEnvVar)
	}

	raw := []byte(inline)
	origin := fenceKeyEnvVar

	if path != "" {
		origin = fenceKeyFileEnvVar

		info, err := os.Stat(path)
		if err != nil {
			return nil, "", fmt.Errorf("%s %q: %w", fenceKeyFileEnvVar, path, err)
		}
		if info.IsDir() {
			return nil, "", fmt.Errorf("%s %q: is a directory, expected a file", fenceKeyFileEnvVar, path)
		}
		// Warn rather than fail: a read-only ConfigMap-style mount can land
		// at 0444 for reasons outside the operator's control, and refusing
		// to start would be worse than flagging it. A private signing key
		// readable by other local users is still worth a log line.
		if perm := info.Mode().Perm(); perm&0o077 != 0 {
			slog.Warn("fence signing key file is readable beyond its owner",
				"path", path,
				"mode", fmt.Sprintf("%04o", perm),
				"hint", "chmod 600 the key file, or mount it with restrictive permissions")
		}

		b, err := os.ReadFile(path)
		if err != nil {
			return nil, "", fmt.Errorf("%s %q: %w", fenceKeyFileEnvVar, path, err)
		}
		raw = b
	}

	key, format, err := parseFenceSigningKey(raw)
	if err != nil {
		return nil, "", fmt.Errorf("%s: %w", origin, err)
	}
	return key, origin + " (" + format + ")", nil
}

// parseFenceSigningKey decodes Ed25519 private key material in any of the
// accepted encodings, auto-detecting which one it was given.
//
// Every error return is written to be actionable without echoing any part of
// the input: an operator whose key is malformed needs to know what shape was
// expected, and a log or a CI transcript must never end up holding fragments
// of a signing key.
func parseFenceSigningKey(raw []byte) (ed25519.PrivateKey, string, error) {
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" {
		return nil, "", errors.New("key material is empty")
	}

	// PEM first: it is what `openssl genpkey` emits and the only encoding
	// that self-identifies, so detecting it is unambiguous.
	if strings.Contains(trimmed, "-----BEGIN") {
		block, _ := pem.Decode([]byte(trimmed))
		if block == nil {
			return nil, "", errors.New("input looks like PEM but no complete PEM block could be decoded " +
				"(check for truncation, or for a value that lost its newlines passing through the environment)")
		}
		if len(block.Headers) > 0 {
			// Headers on a private key block almost always mean the legacy
			// encrypted-PEM format, which x509.ParsePKCS8PrivateKey cannot
			// read. Say so, rather than surfacing an ASN.1 parse error.
			return nil, "", errors.New("PEM block carries headers, which usually indicates an encrypted key; " +
				"decrypt it first (`openssl pkcs8 -topk8 -nocrypt -in enc.pem -out plain.pem`)")
		}
		if block.Type != "PRIVATE KEY" {
			return nil, "", fmt.Errorf("PEM block type is %q, expected %q (PKCS#8); "+
				"convert with `openssl pkcs8 -topk8 -nocrypt`", block.Type, "PRIVATE KEY")
		}
		key, err := parsePKCS8Ed25519(block.Bytes)
		if err != nil {
			return nil, "", err
		}
		return key, "PKCS#8 PEM", nil
	}

	// Otherwise base64. Strip interior whitespace so a value wrapped across
	// lines in a .env file or a Kubernetes manifest still works.
	compact := strings.Join(strings.Fields(trimmed), "")
	decoded, err := decodeBase64Flexible(compact)
	if err != nil {
		return nil, "", fmt.Errorf("not PKCS#8 PEM, and not decodable as base64: %w", err)
	}

	switch len(decoded) {
	case ed25519.SeedSize: // 32
		if isAllZero(decoded) {
			return nil, "", errors.New("key seed is all zero bytes, which is a placeholder rather than a key; " +
				"generate one with `openssl rand -base64 32`")
		}
		return ed25519.NewKeyFromSeed(decoded), "base64 seed", nil

	case ed25519.PrivateKeySize: // 64
		key := ed25519.PrivateKey(decoded)
		if isAllZero(key.Seed()) {
			return nil, "", errors.New("key seed is all zero bytes, which is a placeholder rather than a key; " +
				"generate one with `openssl genpkey -algorithm ed25519`")
		}
		// An Ed25519 private key is seed||public. Re-derive the public half
		// from the seed and require it to match: this catches a truncated,
		// concatenated, or otherwise corrupted 64-byte blob that would
		// otherwise sign happily while producing signatures no verifier
		// holding the advertised public key can check.
		if !bytes.Equal(ed25519.NewKeyFromSeed(key.Seed()), key) {
			return nil, "", errors.New("64-byte key is internally inconsistent: its public half does not match " +
				"the public key derived from its seed (the value is probably corrupted or wrongly assembled)")
		}
		return key, "base64 private key", nil

	default:
		// Could still be base64-wrapped PKCS#8 DER, which has no fixed
		// length. Try it before giving up.
		if key, derErr := parsePKCS8Ed25519(decoded); derErr == nil {
			return key, "base64 PKCS#8 DER", nil
		}
		return nil, "", fmt.Errorf("decoded to %d bytes, which is not a recognised Ed25519 key encoding; "+
			"expected %d (seed), %d (private key), or PKCS#8 DER",
			len(decoded), ed25519.SeedSize, ed25519.PrivateKeySize)
	}
}

// parsePKCS8Ed25519 unwraps a PKCS#8 DER blob and asserts it holds an Ed25519
// key. The type assertion matters: PKCS#8 is a container format, so an RSA or
// ECDSA key parses perfectly well here and would only fail later, at signing
// time, inside every tool call.
func parsePKCS8Ed25519(der []byte) (ed25519.PrivateKey, error) {
	parsed, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, fmt.Errorf("could not parse PKCS#8 private key: %w", err)
	}
	key, ok := parsed.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("PKCS#8 container holds a %T, but fence signing requires an Ed25519 key "+
			"(generate one with `openssl genpkey -algorithm ed25519`)", parsed)
	}
	return key, nil
}

// decodeBase64Flexible accepts standard and URL-safe base64, padded or not.
// Operators paste key material out of a variety of tools and the alphabet or
// padding it arrives in is not something they should have to care about.
func decodeBase64Flexible(s string) ([]byte, error) {
	encodings := []*base64.Encoding{
		base64.StdEncoding,
		base64.RawStdEncoding,
		base64.URLEncoding,
		base64.RawURLEncoding,
	}
	var firstErr error
	for _, enc := range encodings {
		b, err := enc.DecodeString(s)
		if err == nil {
			return b, nil
		}
		if firstErr == nil {
			firstErr = err
		}
	}
	return nil, firstErr
}

// isAllZero reports whether b consists entirely of zero bytes. Used to reject
// the all-zero seed, which is a valid Ed25519 seed mathematically but in
// practice only ever appears as an unfilled placeholder in a config template.
func isAllZero(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return true
}

// resolveFenceKeypair returns the operator-supplied keypair when one was
// configured, and a freshly generated ephemeral one otherwise.
//
// Keeping the branch here rather than in NewServer means a Server constructed
// directly in tests — which passes a zero Config, and therefore a nil key —
// keeps getting a fresh keypair exactly as before.
func resolveFenceKeypair(configured ed25519.PrivateKey) (ed25519.PublicKey, ed25519.PrivateKey) {
	if len(configured) == 0 {
		return generateFenceKeypair()
	}

	// Non-empty but not a well-formed key can only mean a caller populated
	// Config.FenceKey without going through loadFenceSigningKey. Panic rather
	// than fall back: silently reverting to an ephemeral key would leave a
	// deployment that believes its fingerprint is pinned signing with a key
	// nothing downstream recognises, and the only symptom would be a verifier
	// rejecting every fence.
	if len(configured) != ed25519.PrivateKeySize {
		panic(fmt.Sprintf("fence signing key is %d bytes, want %d — populate Config.FenceKey via loadFenceSigningKey",
			len(configured), ed25519.PrivateKeySize))
	}

	pub, ok := configured.Public().(ed25519.PublicKey)
	if !ok {
		// Unreachable today: ed25519.PrivateKey.Public always returns an
		// ed25519.PublicKey. Guarded rather than asserted so a future stdlib
		// change surfaces here instead of as a nil key at the first tool call.
		panic("ed25519 private key did not yield an ed25519 public key")
	}
	return pub, configured
}

// fenceKeyLabel renders the banner value for the fence signing key: the public
// key fingerprint plus whether it survives a restart. Operators wiring up a
// verifying gateway need the persistence state at a glance, because it decides
// whether the fingerprint they pin is stable or has to be re-read after every
// deploy.
func fenceKeyLabel(pub ed25519.PublicKey, source string) string {
	fp := fenceKeyFingerprint(pub)
	if source == "" {
		return fp + " (ephemeral, rotates on restart)"
	}
	return fp + " (persistent, from " + source + ")"
}
