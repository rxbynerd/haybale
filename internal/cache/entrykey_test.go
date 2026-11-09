package cache

import (
	"bytes"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"
)

// TestEntryKeyKnownAnswer pins the per-entry key derivation: HKDF-SHA256 of
// the master sealing key (itself HKDF of the cache key with the sealing
// info) with the entry salt and the entry info string. A change to either
// info string, the salt position or the derivation order changes this
// value and makes every stored entry unreadable, so the test fails loudly.
func TestEntryKeyKnownAnswer(t *testing.T) {
	kr := testKeyring(t) // cache key 0x42 repeated
	salt := make([]byte, saltLen)
	for i := range salt {
		salt[i] = byte(i)
	}
	master, err := hkdf.Key(sha256.New, testKey(0x42), nil, "haybale response cache entry sealing v1", KeySize)
	if err != nil {
		t.Fatal(err)
	}
	want, err := hkdf.Key(sha256.New, master, salt, "haybale response cache entry key v1", KeySize)
	if err != nil {
		t.Fatal(err)
	}
	const known = "efd9976a6f27b7315078155ee83a87b505e1328542f8fcdd99c4cc7065b29978"
	if hex.EncodeToString(want) != known {
		t.Fatalf("reference derivation = %x, want the pinned value %s", want, known)
	}
	got := deriveEntryKey(kr.sealing[kr.ActiveID()], salt)
	if hex.EncodeToString(got[:]) != known {
		t.Fatalf("deriveEntryKey = %x, want %s", got, known)
	}
}

// TestEntryKeysDifferPerSalt confirms two entries sealed under one cache
// key with identical bodies and headers share neither salt nor ciphertext,
// and that equal nonce prefixes and counters would still encrypt under
// different AES keys because the salt selects the key.
func TestEntryKeysDifferPerSalt(t *testing.T) {
	kr := testKeyring(t)
	a := sealBytes(t, kr, testHeader(), []byte("same body"))
	b := sealBytes(t, kr, testHeader(), []byte("same body"))
	saltAt := len(magic) + 2 + keyIDLen
	if bytes.Equal(a[saltAt:saltAt+saltLen], b[saltAt:saltAt+saltLen]) {
		t.Fatal("two entries share a salt")
	}
	if bytes.Equal(a[headerFixedPrefix:], b[headerFixedPrefix:]) {
		t.Fatal("two entries with the same body share ciphertext")
	}
	master := kr.sealing[kr.ActiveID()]
	k1 := deriveEntryKey(master, a[saltAt:saltAt+saltLen])
	k2 := deriveEntryKey(master, b[saltAt:saltAt+saltLen])
	if k1 == k2 {
		t.Fatal("different salts derived the same entry key")
	}
	if again := deriveEntryKey(master, a[saltAt:saltAt+saltLen]); again != k1 {
		t.Fatal("derivation is not deterministic")
	}
}

// TestSealedSaltIsAuthenticated confirms flipping any salt byte fails the
// header seal: the salt is part of the preamble, which is the header's
// associated data, and it selects the key the header was sealed under.
func TestSealedSaltIsAuthenticated(t *testing.T) {
	kr := testKeyring(t)
	entry := sealBytes(t, kr, testHeader(), []byte("payload"))
	saltAt := len(magic) + 2 + keyIDLen
	for i := range saltLen {
		mutated := bytes.Clone(entry)
		mutated[saltAt+i] ^= 0x01
		if _, err := readEntry(kr, mutated); !errors.Is(err, ErrIntegrity) {
			t.Fatalf("salt byte %d flipped: err = %v, want ErrIntegrity", i, err)
		}
	}
}

// TestSealedSizeMatchesBytesWritten confirms SealedSize is exact for
// bodies written without Flush across segment boundaries, with the
// 37-byte preamble.
func TestSealedSizeMatchesBytesWritten(t *testing.T) {
	if preambleLen != 37 {
		t.Fatalf("preambleLen = %d, want 37 (magic 4, version 2, key id 8, salt 16, nonce prefix 7)", preambleLen)
	}
	kr := testKeyring(t)
	for _, n := range []int{0, 1, 100, SegmentSize - 1, SegmentSize, SegmentSize + 1, 3*SegmentSize + 17} {
		entry := sealBytes(t, kr, testHeader(), randomBody(t, n))
		if got, want := int64(len(entry)), SealedSize(int64(n)); got != want {
			t.Errorf("body %d: wrote %d sealed bytes, SealedSize = %d", n, got, want)
		}
	}
}
