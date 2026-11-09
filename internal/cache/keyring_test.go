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
	if want := hex.EncodeToString(sum[:])[:8]; kr.ActiveID() != want {
		t.Fatalf("ActiveID() = %q, want %q", kr.ActiveID(), want)
	}
	if (Keyring{}).ActiveID() != "" {
		t.Fatal("zero Keyring ActiveID() is not empty")
	}
}

func TestKeyringCopiesKey(t *testing.T) {
	key := testKey(3)
	kr, err := NewKeyring(key)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	w, err := NewSealedWriter(&buf, kr, Header{})
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	key[0] ^= 0xff
	if _, err := NewSealedReader(bytes.NewReader(buf.Bytes()), kr); err != nil {
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
	if a.ActiveID() == b.ActiveID() {
		t.Fatalf("two ephemeral keyrings share id %q", a.ActiveID())
	}
}

func TestKeyringWithPrevious(t *testing.T) {
	oldKR, err := NewKeyring(testKey(1))
	if err != nil {
		t.Fatal(err)
	}
	newKR, err := NewKeyring(testKey(2))
	if err != nil {
		t.Fatal(err)
	}
	entry := sealBytes(t, oldKR, Header{}, []byte("old entry"))

	if _, err := NewSealedReader(bytes.NewReader(entry), newKR); err == nil {
		t.Fatal("new key opened an entry sealed under the old key")
	}
	rotated, err := newKR.WithPrevious(testKey(1))
	if err != nil {
		t.Fatal(err)
	}
	if rotated.ActiveID() != newKR.ActiveID() {
		t.Fatalf("WithPrevious changed the active id to %q", rotated.ActiveID())
	}
	if got := openBytes(t, rotated, entry); string(got) != "old entry" {
		t.Fatalf("rotated keyring read %q", got)
	}
	if _, ok := newKR.aead(oldKR.ActiveID()); ok {
		t.Fatal("WithPrevious mutated the receiver")
	}
	again, err := rotated.WithPrevious(testKey(2))
	if err != nil {
		t.Fatalf("re-adding the active key: %v", err)
	}
	if len(again.sealing) != 2 {
		t.Fatalf("keyring holds %d keys, want 2", len(again.sealing))
	}
	if _, err := newKR.WithPrevious(make([]byte, 5)); err == nil {
		t.Fatal("WithPrevious accepted a short key")
	}
	if _, err := (Keyring{}).WithPrevious(testKey(1)); err == nil {
		t.Fatal("WithPrevious on the zero Keyring succeeded")
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
