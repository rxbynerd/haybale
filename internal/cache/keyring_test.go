package cache

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"
)

func testKey(b byte) []byte { return bytes.Repeat([]byte{b}, KeySize) }

func TestNewKeyringRequires32Bytes(t *testing.T) {
	for _, n := range []int{0, 16, 31, 33, 64} {
		if _, err := NewKeyring(make([]byte, n)); err == nil {
			t.Errorf("NewKeyring(%d bytes) error = nil, want error", n)
		}
	}
	if _, err := NewKeyring(testKey(1)); err != nil {
		t.Fatalf("NewKeyring(32 bytes) error = %v", err)
	}
}

func TestKeyringActiveIDIsSHA256Prefix(t *testing.T) {
	key := testKey(7)
	kr, err := NewKeyring(key)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(key)
	if want := hex.EncodeToString(sum[:])[:8]; kr.activeID() != want {
		t.Fatalf("activeID() = %q, want %q", kr.activeID(), want)
	}
	if (Keyring{}).activeID() != "" {
		t.Fatal("zero Keyring activeID() is not empty")
	}
}

func TestKeyringCopiesKey(t *testing.T) {
	key := testKey(3)
	kr, err := NewKeyring(key)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	w, err := newSealedWriter(&buf, kr, entryHeader{})
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	key[0] ^= 0xff
	if _, err := newSealedReader(bytes.NewReader(buf.Bytes()), kr); err != nil {
		t.Fatalf("entry no longer opens after mutating the caller's key slice: %v", err)
	}
}

func TestEphemeralKeyringsDiffer(t *testing.T) {
	a, err := EphemeralKeyring()
	if err != nil {
		t.Fatal(err)
	}
	b, err := EphemeralKeyring()
	if err != nil {
		t.Fatal(err)
	}
	if a.activeID() == b.activeID() {
		t.Fatalf("two ephemeral keyrings share id %q", a.activeID())
	}
}

func TestDecode32(t *testing.T) {
	// 0xfb and 0xff encode to '+' and '/' in the standard alphabet and
	// '-' and '_' in the URL alphabet.
	key := bytes.Repeat([]byte{0xfb, 0xff, 0x3e}, 11)[:KeySize]
	valid := map[string]string{
		"std":        base64.StdEncoding.EncodeToString(key),
		"raw std":    base64.RawStdEncoding.EncodeToString(key),
		"url":        base64.URLEncoding.EncodeToString(key),
		"raw url":    base64.RawURLEncoding.EncodeToString(key),
		"whitespace": "  " + base64.StdEncoding.EncodeToString(key) + "\n",
	}
	for name, in := range valid {
		got, err := Decode32(in)
		if err != nil {
			t.Errorf("%s: Decode32 error = %v", name, err)
			continue
		}
		if !bytes.Equal(got, key) {
			t.Errorf("%s: Decode32 = %x, want %x", name, got, key)
		}
	}

	secret := "not*base64*" + strings.Repeat("s", 40)
	invalid := map[string]string{
		"empty":      "",
		"short":      base64.StdEncoding.EncodeToString(key[:16]),
		"long":       base64.StdEncoding.EncodeToString(append(key, 0)),
		"not base64": secret,
	}
	for name, in := range invalid {
		_, err := Decode32(in)
		if err == nil {
			t.Errorf("%s: Decode32 error = nil", name)
			continue
		}
		if in != "" && strings.Contains(err.Error(), in) {
			t.Errorf("%s: error %q contains the input", name, err)
		}
	}
}

func TestPathHashKnownAnswer(t *testing.T) {
	kr, err := NewKeyring(testKey(0x2a))
	if err != nil {
		t.Fatal(err)
	}
	var digest [32]byte
	for i := range digest {
		digest[i] = 1
	}
	// HMAC-SHA256(HKDF-SHA256(key, no salt, pathKeyInfo), digest), computed
	// independently of this package.
	const want = "f9c1b46d951e0c6251eb76a31f8f5172cfaff30c0b72d3f2772fd8d7ff76a18d"
	if got := kr.pathHash(digest); hex.EncodeToString(got[:]) != want {
		t.Errorf("pathHash = %x, want %s", got, want)
	}
}

func TestPathHashIsKeyedAndStable(t *testing.T) {
	a, err := NewKeyring(testKey(1))
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewKeyring(testKey(2))
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte("fetch request"))
	if a.pathHash(digest) != a.pathHash(digest) {
		t.Error("pathHash is not stable under one key")
	}
	if a.pathHash(digest) == b.pathHash(digest) {
		t.Error("pathHash is the same under two keys")
	}
	if a.pathHash(digest) == digest {
		t.Error("pathHash returned the digest unchanged")
	}
	infos := map[string]bool{sealingKeyInfo: true, entryKeyInfo: true, pathKeyInfo: true}
	if len(infos) != 3 {
		t.Error("the path key info string repeats another derivation's")
	}
}
