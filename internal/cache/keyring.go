package cache

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

// KeySize is the length in bytes of a cache key.
const KeySize = 32

// keyIDLen is the length of a key id: hex characters of the key's SHA-256.
const keyIDLen = 8

// sealingKeyInfo separates the AES-256-GCM sealing key from other uses of
// the configured cache key, such as the RepoHash HMAC.
const sealingKeyInfo = "haybale response cache entry sealing v1"

// Keyring holds the active cache key and any previous keys, indexed by key
// id. Entries are sealed under the active key and opened under whichever
// key their preamble names. A Keyring is an immutable value and is safe for
// concurrent use; the zero Keyring holds no keys and seals nothing.
type Keyring struct {
	active string
	// sealing maps a key id to the sealing key derived from that cache key.
	sealing map[string][KeySize]byte
}

// NewKeyring returns a Keyring whose active key is active, which must be
// exactly KeySize bytes. The key is copied.
func NewKeyring(active []byte) (Keyring, error) {
	id, sealing, err := deriveKey(active)
	if err != nil {
		return Keyring{}, err
	}
	return Keyring{active: id, sealing: map[string][KeySize]byte{id: sealing}}, nil
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

// WithPrevious returns a copy of k that can also open entries sealed under
// key, a previous cache key of KeySize bytes. The active key is unchanged.
// Adding a key already in k is a no-op; a different key whose id collides
// with one in k is an error.
func (k Keyring) WithPrevious(key []byte) (Keyring, error) {
	if k.active == "" {
		return Keyring{}, errors.New("cache: keyring has no active key")
	}
	id, sealing, err := deriveKey(key)
	if err != nil {
		return Keyring{}, err
	}
	if existing, ok := k.sealing[id]; ok {
		if existing != sealing {
			return Keyring{}, fmt.Errorf("cache: previous key's id %s collides with a different key in the keyring", id)
		}
		return k, nil
	}
	next := Keyring{active: k.active, sealing: make(map[string][KeySize]byte, len(k.sealing)+1)}
	for kid, sk := range k.sealing {
		next.sealing[kid] = sk
	}
	next.sealing[id] = sealing
	return next, nil
}

// ActiveID returns the id of the active key, or "" for the zero Keyring. A
// key id is the first 8 hex characters of the SHA-256 of the cache key.
func (k Keyring) ActiveID() string { return k.active }

// aead returns an AES-256-GCM instance for the key with id.
func (k Keyring) aead(id string) (cipher.AEAD, bool) {
	sealing, ok := k.sealing[id]
	if !ok {
		return nil, false
	}
	block, err := aes.NewCipher(sealing[:])
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

// deriveKey validates key and returns its id and derived sealing key.
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
