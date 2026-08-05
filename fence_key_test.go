package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// ── helpers ───────────────────────────────────────────────────────────────────

// testKeyEncodings returns one Ed25519 private key rendered in every encoding
// loadFenceSigningKey claims to accept, keyed by the format label the parser
// is expected to report.  Generating the key here rather than checking in
// fixtures keeps the suite free of committed key material.
func testKeyEncodings(t *testing.T) (ed25519.PrivateKey, map[string]string) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating test key: %v", err)
	}

	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("marshalling PKCS#8: %v", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})

	return priv, map[string]string{
		"PKCS#8 PEM":         string(pemBytes),
		"base64 PKCS#8 DER":  base64.StdEncoding.EncodeToString(der),
		"base64 seed":        base64.StdEncoding.EncodeToString(priv.Seed()),
		"base64 private key": base64.StdEncoding.EncodeToString(priv),
	}
}

// ── parseFenceSigningKey: accepted encodings ──────────────────────────────────

// Every accepted encoding of the same key must produce the same key bytes and
// report the format it actually detected.  A mismatch here means an operator
// could switch encodings during a rotation and silently start signing with a
// different key than the one their verifier pinned.
func TestParseFenceSigningKey_EncodingsAgree(t *testing.T) {
	want, encodings := testKeyEncodings(t)

	for wantFormat, encoded := range encodings {
		t.Run(wantFormat, func(t *testing.T) {
			got, gotFormat, err := parseFenceSigningKey([]byte(encoded))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !bytes.Equal(got, want) {
				t.Error("parsed key differs from the key that was encoded")
			}
			if gotFormat != wantFormat {
				t.Errorf("format = %q, want %q", gotFormat, wantFormat)
			}
		})
	}
}

// Base64 values routinely arrive wrapped across lines from YAML block scalars
// and .env files.  Interior whitespace must not defeat parsing.
func TestParseFenceSigningKey_WrappedBase64(t *testing.T) {
	want, encodings := testKeyEncodings(t)
	flat := encodings["base64 PKCS#8 DER"]
	wrapped := flat[:20] + "\n   " + flat[20:40] + "\n\t" + flat[40:]

	got, _, err := parseFenceSigningKey([]byte(wrapped))
	if err != nil {
		t.Fatalf("wrapped base64 should parse: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Error("wrapped base64 produced a different key")
	}
}

// Operators paste key material out of tools that disagree about alphabet and
// padding; all four base64 variants must work.
func TestParseFenceSigningKey_Base64Alphabets(t *testing.T) {
	seed := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		t.Fatalf("reading random seed: %v", err)
	}

	for name, enc := range map[string]*base64.Encoding{
		"std":    base64.StdEncoding,
		"rawstd": base64.RawStdEncoding,
		"url":    base64.URLEncoding,
		"rawurl": base64.RawURLEncoding,
	} {
		t.Run(name, func(t *testing.T) {
			got, _, err := parseFenceSigningKey([]byte(enc.EncodeToString(seed)))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !bytes.Equal(got.Seed(), seed) {
				t.Error("seed did not survive the round trip")
			}
		})
	}
}

// ── parseFenceSigningKey: rejections ──────────────────────────────────────────

func TestParseFenceSigningKey_Rejects(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating test key: %v", err)
	}
	// A 64-byte blob whose public half no longer matches its seed.
	corrupt := append([]byte(nil), priv...)
	corrupt[ed25519.SeedSize+4] ^= 0xff

	// A non-Ed25519 key in a PKCS#8 container parses fine as PKCS#8 and must
	// be rejected on the type assertion, not on the ASN.1 parse. ECDSA rather
	// than RSA purely because it generates fast enough not to slow the suite.
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating ECDSA key: %v", err)
	}
	ecDER, err := x509.MarshalPKCS8PrivateKey(ecKey)
	if err != nil {
		t.Fatalf("marshalling ECDSA PKCS#8: %v", err)
	}
	ecPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: ecDER}))

	cases := []struct {
		name       string
		input      string
		wantDetail string
	}{
		{"empty", "   \n\t ", "empty"},
		{"not base64", "this is not a key at all!!", "base64"},
		{"zero seed", base64.StdEncoding.EncodeToString(make([]byte, ed25519.SeedSize)), "all zero"},
		{"zero private key", base64.StdEncoding.EncodeToString(make([]byte, ed25519.PrivateKeySize)), "all zero"},
		{"inconsistent private key", base64.StdEncoding.EncodeToString(corrupt), "inconsistent"},
		{"wrong length", base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{9}, 48)), "48 bytes"},
		{"ecdsa key", ecPEM, "Ed25519"},
		{"truncated pem", "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2Vw", "PEM"},
		{"wrong pem type", "-----BEGIN EC PRIVATE KEY-----\nMHcCAQEEIA==\n-----END EC PRIVATE KEY-----\n", "PKCS#8"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := parseFenceSigningKey([]byte(tc.input))
			if err == nil {
				t.Fatal("expected an error, got none")
			}
			if !strings.Contains(err.Error(), tc.wantDetail) {
				t.Errorf("error %q does not mention %q, so it is not actionable", err, tc.wantDetail)
			}
			// Key material must never reach a log or a CI transcript.
			if len(tc.input) > 24 && strings.Contains(err.Error(), tc.input) {
				t.Error("error message echoed the supplied key material")
			}
		})
	}
}

// ── loadFenceSigningKey ───────────────────────────────────────────────────────

// The whole point of the change: unset means unchanged behaviour.
func TestLoadFenceSigningKey_UnsetIsEphemeral(t *testing.T) {
	key, source, err := loadFenceSigningKey("", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if key != nil {
		t.Error("no key should be returned when neither variable is set")
	}
	if source != "" {
		t.Errorf("source = %q, want empty", source)
	}
}

// Whitespace-only values are treated as unset, not as a malformed key — a
// blank line in an env file must not stop the server.
func TestLoadFenceSigningKey_BlankIsUnset(t *testing.T) {
	key, _, err := loadFenceSigningKey("  ", "\t\n")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if key != nil {
		t.Error("whitespace-only config should be treated as unset")
	}
}

func TestLoadFenceSigningKey_BothSetIsError(t *testing.T) {
	_, _, err := loadFenceSigningKey("inline", "/some/path")
	if err == nil {
		t.Fatal("setting both variables should be an error, not a precedence decision")
	}
	if !strings.Contains(err.Error(), fenceKeyEnvVar) || !strings.Contains(err.Error(), fenceKeyFileEnvVar) {
		t.Errorf("error %q should name both variables", err)
	}
}

func TestLoadFenceSigningKey_FromFile(t *testing.T) {
	want, encodings := testKeyEncodings(t)
	path := filepath.Join(t.TempDir(), "fence.pem")
	if err := os.WriteFile(path, []byte(encodings["PKCS#8 PEM"]), 0o600); err != nil {
		t.Fatalf("writing key file: %v", err)
	}

	got, source, err := loadFenceSigningKey("", path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Error("key read from file differs from the key written")
	}
	if !strings.Contains(source, fenceKeyFileEnvVar) || !strings.Contains(source, "PKCS#8 PEM") {
		t.Errorf("source = %q, should name the variable and the detected format", source)
	}
}

func TestLoadFenceSigningKey_FileErrors(t *testing.T) {
	if _, _, err := loadFenceSigningKey("", filepath.Join(t.TempDir(), "absent.pem")); err == nil {
		t.Error("a missing key file should fail startup")
	}
	if _, _, err := loadFenceSigningKey("", t.TempDir()); err == nil {
		t.Error("a directory should fail startup")
	}
}

// Errors must name the variable the operator actually set, or they will go
// looking in the wrong place.
func TestLoadFenceSigningKey_ErrorNamesSource(t *testing.T) {
	_, _, err := loadFenceSigningKey("not-a-key!!", "")
	if err == nil {
		t.Fatal("expected an error")
	}
	if !strings.Contains(err.Error(), fenceKeyEnvVar) {
		t.Errorf("error %q should name %s", err, fenceKeyEnvVar)
	}
}

// ── resolveFenceKeypair ───────────────────────────────────────────────────────

// A nil configured key must still yield a fresh random keypair every time,
// which is what every existing test and every unconfigured deployment relies on.
func TestResolveFenceKeypair_NilGeneratesFresh(t *testing.T) {
	pub1, priv1 := resolveFenceKeypair(nil)
	pub2, _ := resolveFenceKeypair(nil)

	if len(pub1) != ed25519.PublicKeySize || len(priv1) != ed25519.PrivateKeySize {
		t.Fatalf("generated keypair has wrong sizes: pub=%d priv=%d", len(pub1), len(priv1))
	}
	if bytes.Equal(pub1, pub2) {
		t.Error("two ephemeral keypairs were identical")
	}
	if !bytes.Equal(priv1.Public().(ed25519.PublicKey), pub1) {
		t.Error("returned public key does not match the returned private key")
	}
}

// A configured key must be used verbatim, and must survive a simulated
// restart with the same fingerprint — the property a verifying gateway pins.
func TestResolveFenceKeypair_ConfiguredIsStable(t *testing.T) {
	want, encodings := testKeyEncodings(t)
	path := filepath.Join(t.TempDir(), "fence.pem")
	if err := os.WriteFile(path, []byte(encodings["PKCS#8 PEM"]), 0o600); err != nil {
		t.Fatalf("writing key file: %v", err)
	}

	var fingerprints []string
	for i := 0; i < 2; i++ { // two "process starts"
		loaded, _, err := loadFenceSigningKey("", path)
		if err != nil {
			t.Fatalf("load %d: %v", i, err)
		}
		pub, priv := resolveFenceKeypair(loaded)
		if !bytes.Equal(priv, want) {
			t.Fatalf("start %d: configured key was not used verbatim", i)
		}
		if !bytes.Equal(pub, want.Public().(ed25519.PublicKey)) {
			t.Fatalf("start %d: derived public key is wrong", i)
		}
		fingerprints = append(fingerprints, fenceKeyFingerprint(pub))
	}
	if fingerprints[0] != fingerprints[1] {
		t.Errorf("fingerprint changed across restarts: %q then %q", fingerprints[0], fingerprints[1])
	}
}

// An end-to-end check that a loaded key produces fences a holder of the
// published public key can verify — the property the whole feature exists for.
func TestConfiguredKeySignsVerifiableFences(t *testing.T) {
	_, encodings := testKeyEncodings(t)
	loaded, _, err := loadFenceSigningKey(encodings["base64 seed"], "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	pub, priv := resolveFenceKeypair(loaded)
	s := &Server{fencePublicKey: pub, fenceSigningKey: priv}

	content := "untrusted page text"
	meta := fenceMetadata{
		Type:      FenceTypeContent,
		Rating:    FenceUntrusted,
		Source:    "https://example.com",
		Timestamp: time.Now(),
		Nonce:     "deadbeef",
	}
	canonical := meta.canonicalAttributes()
	sigB64, err := computeFenceSignature(s.fenceSigningKey, content, canonical)
	if err != nil {
		t.Fatalf("signing: %v", err)
	}
	sig, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		t.Fatalf("decoding signature: %v", err)
	}
	msg, err := buildFenceSigningInput(content, canonical)
	if err != nil {
		t.Fatalf("building signing input: %v", err)
	}

	// Verify against the key as a gateway would obtain it: decoded from the
	// base64 form published at /fence/public-key.
	published, err := base64.StdEncoding.DecodeString(fencePublicKeyBase64(s.fencePublicKey))
	if err != nil {
		t.Fatalf("decoding published public key: %v", err)
	}
	if !ed25519.Verify(published, msg, sig) {
		t.Error("fence signed with the configured key did not verify against the published public key")
	}
}

// ── fenceKeyLabel ─────────────────────────────────────────────────────────────

func TestFenceKeyLabel(t *testing.T) {
	pub, _ := resolveFenceKeypair(nil)
	fp := fenceKeyFingerprint(pub)

	ephemeral := fenceKeyLabel(pub, "")
	if !strings.Contains(ephemeral, fp) || !strings.Contains(ephemeral, "ephemeral") {
		t.Errorf("ephemeral label = %q, want fingerprint and %q", ephemeral, "ephemeral")
	}

	persistent := fenceKeyLabel(pub, fenceKeyEnvVar+" (base64 seed)")
	if !strings.Contains(persistent, fp) || !strings.Contains(persistent, "persistent") {
		t.Errorf("persistent label = %q, want fingerprint and %q", persistent, "persistent")
	}
	if !strings.Contains(persistent, fenceKeyEnvVar) {
		t.Errorf("persistent label %q should name the source", persistent)
	}
}

// A Config.FenceKey populated without going through the loader is a
// programming error, and must not silently degrade to an ephemeral key.
func TestResolveFenceKeypair_MalformedPanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Error("a wrong-length key should panic, not fall back to ephemeral")
		}
	}()
	resolveFenceKeypair(ed25519.PrivateKey(make([]byte, 32)))
}

// An explicitly empty (non-nil, zero-length) key is still "unset".
func TestResolveFenceKeypair_EmptyIsEphemeral(t *testing.T) {
	pub, priv := resolveFenceKeypair(ed25519.PrivateKey{})
	if len(pub) != ed25519.PublicKeySize || len(priv) != ed25519.PrivateKeySize {
		t.Fatal("empty key should have produced a fresh ephemeral keypair")
	}
}
