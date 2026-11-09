package cache

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/rxbynerd/haybale/internal/gitproto"
)

// KeySize is the length in bytes of a cache key.
const KeySize = 32

// keyIDLen is the length of a key id: hex characters of the key's SHA-256.
const keyIDLen = 8

// sealingKeyInfo separates the master sealing key from other uses of the
// configured cache key, such as the RepoHash HMAC. entryKeyInfo derives
// each entry's AES-256-GCM key from the master sealing key and the entry's
// salt. pathKeyInfo derives the key that turns a request digest into the
// KeyHash in entry names. All three strings are part of the storage
// format.
const (
	sealingKeyInfo = "haybale response cache entry sealing v1"
	entryKeyInfo   = "haybale response cache entry key v1"
	pathKeyInfo    = "haybale response cache path key v1"
)

// Keyring holds the active cache key. Entries are sealed under it and
// opened only when their preamble names its id; rotating the key is a cold
// cache. A Keyring is an immutable value and is safe for concurrent use;
// the zero Keyring holds no key and seals nothing.
type Keyring struct {
	active string
	// key is the raw active cache key, the HMAC key for RepoHash.
	key []byte
	// path is the HMAC key for pathHash, derived from key.
	path []byte
	// sealing maps a key id to the master sealing key derived from that
	// cache key; entry keys derive from it and a per-entry salt.
	sealing map[string][KeySize]byte
}

// NewKeyring returns a Keyring whose active key is active, which must be
// exactly KeySize bytes. The key is copied.
func NewKeyring(active []byte) (Keyring, error) {
	id, sealing, err := deriveKey(active)
	if err != nil {
		return Keyring{}, err
	}
	path, err := hkdf.Key(sha256.New, active, nil, pathKeyInfo, KeySize)
	if err != nil {
		return Keyring{}, fmt.Errorf("cache: derive path key: %w", err)
	}
	return Keyring{active: id, key: bytes.Clone(active), path: path, sealing: map[string][KeySize]byte{id: sealing}}, nil
}

// EphemeralKeyring returns a Keyring with a random active key. Entries
// sealed under it cannot be opened by any other process.
func EphemeralKeyring() (Keyring, error) {
	key := make([]byte, KeySize)
	if _, err := rand.Read(key); err != nil {
		return Keyring{}, fmt.Errorf("cache: generate ephemeral key: %w", err)
	}
	return NewKeyring(key)
}

// activeID returns the id of the active key, or "" for the zero Keyring. A
// key id is the first 8 hex characters of the SHA-256 of the cache key.
func (k Keyring) activeID() string { return k.active }

// RepoHash returns RepoHash under the active cache key, so that every
// component addressing entries derives the same repository hash from the
// same configured key. baseURL must not be nil.
func (k Keyring) RepoHash(baseURL *url.URL, repo gitproto.Repo) [32]byte {
	return repoHash(k.key, baseURL, repo)
}

// pathHash returns the KeyHash that names the entry for a request whose
// canonical digest is digest: HMAC-SHA256 under the path key, so a reader
// of object names cannot confirm a guessed request without the cache key.
func (k Keyring) pathHash(digest [32]byte) [32]byte {
	mac := hmac.New(sha256.New, k.path)
	mac.Write(digest[:])
	var sum [32]byte
	mac.Sum(sum[:0])
	return sum
}

// holds reports whether the keyring has the key with id.
func (k Keyring) holds(id string) bool {
	_, ok := k.sealing[id]
	return ok
}

// aead returns an AES-256-GCM instance for the entry key derived from the
// key with id and salt. Every entry has its own salt, so entries never
// share an AES key.
func (k Keyring) aead(id string, salt []byte) (cipher.AEAD, bool) {
	sealing, ok := k.sealing[id]
	if !ok {
		return nil, false
	}
	entryKey := deriveEntryKey(sealing, salt)
	block, err := aes.NewCipher(entryKey[:])
	if err != nil {
		// A 32-byte key is always a valid AES key.
		panic(fmt.Sprintf("cache: aes.NewCipher: %v", err))
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(fmt.Sprintf("cache: cipher.NewGCM: %v", err))
	}
	return gcm, true
}

// deriveEntryKey derives an entry's AES key from a master sealing key and
// the entry's salt.
func deriveEntryKey(sealing [KeySize]byte, salt []byte) [KeySize]byte {
	derived, err := hkdf.Key(sha256.New, sealing[:], salt, entryKeyInfo, KeySize)
	if err != nil {
		// Only an invalid hash or length can fail here; both are fixed.
		panic(fmt.Sprintf("cache: derive entry key: %v", err))
	}
	var entryKey [KeySize]byte
	copy(entryKey[:], derived)
	return entryKey
}

// deriveKey validates key and returns its id and derived master sealing
// key.
func deriveKey(key []byte) (string, [KeySize]byte, error) {
	if len(key) != KeySize {
		return "", [KeySize]byte{}, fmt.Errorf("cache: key must be %d bytes, got %d", KeySize, len(key))
	}
	sum := sha256.Sum256(key)
	id := hex.EncodeToString(sum[:])[:keyIDLen]
	derived, err := hkdf.Key(sha256.New, key, nil, sealingKeyInfo, KeySize)
	if err != nil {
		return "", [KeySize]byte{}, fmt.Errorf("cache: derive sealing key: %w", err)
	}
	var sealing [KeySize]byte
	copy(sealing[:], derived)
	return id, sealing, nil
}

// Decode32 decodes a cache key from base64 in the standard or URL-safe
// alphabet, padded or not, ignoring surrounding whitespace. The result must
// be exactly KeySize bytes. Errors never include the input.
func Decode32(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, errors.New("cache: key is empty")
	}
	encodings := []*base64.Encoding{
		base64.StdEncoding, base64.RawStdEncoding,
		base64.URLEncoding, base64.RawURLEncoding,
	}
	for _, enc := range encodings {
		key, err := enc.DecodeString(s)
		if err != nil {
			continue
		}
		if len(key) != KeySize {
			return nil, fmt.Errorf("cache: key must decode to %d bytes, got %d", KeySize, len(key))
		}
		return key, nil
	}
	return nil, errors.New("cache: key is not valid base64")
}
