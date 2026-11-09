package config

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"net/http"
	"os"
	"reflect"
	"regexp"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/rxbynerd/haybale/internal/cache"
	"github.com/rxbynerd/haybale/internal/cache/s3store"
	"github.com/rxbynerd/haybale/internal/observability"
)

// Defaults applied to an enabled CacheConfig by applyDefaults. A disabled
// block receives none of them and stays inert.
const (
	defaultCacheMaxDiskSize  = 10 * gib
	defaultCacheMaxEntrySize = 1 * gib
	// defaultCacheMaxConcurrentFills times defaultCacheMaxEntrySize is
	// the most that fills in flight can reserve: 4GiB of the 10GiB
	// budget, leaving the rest for stored entries.
	defaultCacheMaxConcurrentFills    = 4
	defaultCacheMaxRequestBody        = 1 * mib
	defaultCacheRetention             = "24h"
	defaultCacheRefsMaxAge            = "0s"
	defaultCacheAccessRecheck         = "5m"
	defaultCacheResponseHeaderTimeout = "60s"
	defaultCacheIdleTimeout           = "2m"
	defaultRemoteHeaderTimeout        = "10s"
)

// remoteTypeS3 is the only remote tier implementation.
const remoteTypeS3 = "s3"

// Server-side encryption modes RemoteCacheConfig.SSE accepts.
const (
	remoteSSEAES256 = "AES256"
	remoteSSEKMS    = "aws:kms"
)

const (
	// remoteProbePrefix holds the objects BuildCache reads to check that
	// the bucket is usable: a random key per start, never written, so a
	// healthy bucket answers "not found" and a bucket writer cannot plant
	// the key in advance.
	remoteProbePrefix = "v1/.probe/"
	// remoteProbeTimeout bounds the startup probe of the remote tier.
	remoteProbeTimeout = 30 * time.Second
)

// Binary (IEC) size units, the only units ByteSize accepts.
const (
	kib ByteSize = 1 << (10 * (iota + 1))
	mib
	gib
	tib
)

// byteSizeUnits maps each accepted unit suffix to its multiplier,
// largest first so String can pick the largest exact unit.
var byteSizeUnits = []struct {
	suffix string
	size   ByteSize
}{
	{"TiB", tib},
	{"GiB", gib},
	{"MiB", mib},
	{"KiB", kib},
}

// byteSizePattern matches "<number><unit>" with an optional single space
// before the unit. The number is unsigned digits with an optional
// fractional part, so signs, exponents and surrounding whitespace never
// match. Units are case-sensitive.
var byteSizePattern = regexp.MustCompile(`^([0-9]+(?:\.[0-9]+)?) ?(KiB|MiB|GiB|TiB)$`)

// ByteSize is a size in bytes that unmarshals from a YAML string of the
// form "<number><unit>" with IEC units only: KiB, MiB, GiB, TiB (for
// example "512MiB" or "1.5GiB"). The literal "0", with no unit, is also
// accepted as zero bytes so that an explicit zero selects the default. Any
// other bare integer, an SI unit (KB, MB, GB), a negative value or any
// other form is rejected, so a configured size can never be misread by a
// factor of 1024 or silently taken as bytes.
type ByteSize int64

// UnmarshalYAML parses a scalar node into a ByteSize. A number that does
// not resolve to a whole number of bytes (for example "1.0001KiB") or
// that overflows int64 is rejected. Errors name the YAML line because
// the decoder does not report which field held the value.
func (b *ByteSize) UnmarshalYAML(value *yaml.Node) error {
	if value.Kind != yaml.ScalarNode {
		return fmt.Errorf("line %d: size must be a string such as \"10GiB\"", value.Line)
	}
	if value.Value == "0" {
		*b = 0
		return nil
	}
	match := byteSizePattern.FindStringSubmatch(value.Value)
	if match == nil {
		return fmt.Errorf("line %d: size %q is invalid: want <number><unit> with unit KiB, MiB, GiB or TiB (for example \"10GiB\")", value.Line, value.Value)
	}

	// The pattern guarantees match[1] is a plain decimal number and
	// match[2] is one of byteSizeUnits' suffixes.
	number, _ := new(big.Rat).SetString(match[1])
	for _, u := range byteSizeUnits {
		if u.suffix == match[2] {
			number.Mul(number, new(big.Rat).SetInt64(int64(u.size)))
			break
		}
	}
	if !number.IsInt() {
		return fmt.Errorf("line %d: size %q is not a whole number of bytes", value.Line, value.Value)
	}
	if !number.Num().IsInt64() {
		return fmt.Errorf("line %d: size %q is too large", value.Line, value.Value)
	}
	*b = ByteSize(number.Num().Int64())
	return nil
}

// String renders the size in the largest IEC unit that represents it
// exactly (for example "1GiB" or "1536MiB"). A size that is not a whole
// number of KiB, including zero, renders as a plain byte count ("1500B").
func (b ByteSize) String() string {
	if b > 0 {
		for _, u := range byteSizeUnits {
			if b%u.size == 0 {
				return fmt.Sprintf("%d%s", b/u.size, u.suffix)
			}
		}
	}
	return fmt.Sprintf("%dB", int64(b))
}

// CacheConfig configures the response cache for Git smart HTTP reads.
// The block is off by default: while Enabled is false it is inert, no
// defaults are applied to it and validate accepts any content. See
// docs/design/response-cache.md.
type CacheConfig struct {
	// Enabled turns the cache on. Defaults to false.
	Enabled bool `yaml:"enabled"`
	// Dir is the directory the disk tier stores sealed entries in. It is
	// required when Enabled. The last path element is created with mode
	// 0700 when missing, and the directory must be owned by the process
	// user with no group or other permission bits; that is checked when
	// the directory is opened, not by validate.
	Dir string `yaml:"dir"`
	// KeyEnv names an environment variable holding the 32-byte base64
	// cache key. Optional for a disk-only cache, in which case an
	// ephemeral key is generated and entries do not survive a restart.
	// Like a credential's tokenEnv, the key is never written inline. The
	// variable is read when the cache is built, not by validate, so
	// `haybale policy check` needs no environment.
	KeyEnv string `yaml:"keyEnv"`
	// MaxDiskSize is the disk-tier budget covering committed entries,
	// in-flight fills and evicted entries still held open. Defaults to
	// 10GiB.
	MaxDiskSize ByteSize `yaml:"maxDiskSize"`
	// MaxEntrySize is the largest response stored; larger responses
	// stream through unstored. It must not exceed half of MaxDiskSize,
	// which leaves room for a second fill and for stored entries.
	// Defaults to 1GiB.
	MaxEntrySize ByteSize `yaml:"maxEntrySize"`
	// MaxConcurrentFills bounds simultaneous cache fills; a read that
	// finds no free slot is proxied without the cache. Must be at least
	// 1. Defaults to 4.
	MaxConcurrentFills int `yaml:"maxConcurrentFills"`
	// MaxRequestBody is the largest decoded request body the cache will
	// inspect; a read with a larger body bypasses the cache. Must be
	// greater than zero. Defaults to 1MiB.
	MaxRequestBody ByteSize `yaml:"maxRequestBody"`
	// Retention is a Go duration string: the maximum age of any entry,
	// and the window during which content removed upstream can still be
	// served. Defaults to "24h".
	Retention string `yaml:"retention"`
	// RefsMaxAge is a Go duration string: how long a stored ref
	// advertisement is served without revalidating upstream. "0s" (the
	// default) always revalidates.
	RefsMaxAge string `yaml:"refsMaxAge"`
	// AccessRecheck is a Go duration string: how long after the last
	// successful upstream refs response a pack hit is served without
	// another upstream check. "0s" disables the check. Defaults to "5m".
	// When both are non-zero, RefsMaxAge must be less than AccessRecheck:
	// a refs hit does not renew the access record, so a larger RefsMaxAge
	// would stop packs hitting while refs still hit.
	AccessRecheck string `yaml:"accessRecheck"`
	// ResponseHeaderTimeout is a Go duration string bounding how long a
	// cache fill waits for the upstream's response headers. "0s" applies
	// no bound. It does not affect reads proxied without the cache.
	// Defaults to "60s".
	ResponseHeaderTimeout string `yaml:"responseHeaderTimeout"`
	// IdleTimeout is a Go duration string bounding the gap between body
	// bytes from the upstream during a cache fill. "0s" leaves the gap
	// unbounded. It does not affect reads proxied without the cache.
	// Defaults to "2m".
	IdleTimeout string `yaml:"idleTimeout"`
	// ExposeStatus makes haybale emit a Cache-Status response header.
	// Defaults to false.
	ExposeStatus bool `yaml:"exposeStatus"`
	// Remote configures an optional remote tier shared by every replica.
	// It requires KeyEnv, so that replicas seal and address entries under
	// the same key.
	Remote RemoteCacheConfig `yaml:"remote"`
	// StaleIfErrorFor is a Go duration string: the maximum age of an
	// entry served when upstream cannot answer. Only a zero duration is
	// accepted.
	StaleIfErrorFor string `yaml:"staleIfErrorFor"`

	// The parsed* fields cache the durations validate parsed, for the
	// same reuse-not-reparse reason Config.parsedDrainTimeout exists.
	parsedRetention             time.Duration
	parsedRefsMaxAge            time.Duration
	parsedAccessRecheck         time.Duration
	parsedResponseHeaderTimeout time.Duration
	parsedIdleTimeout           time.Duration
}

// RemoteCacheConfig configures the optional remote cache tier, a prefix
// of an S3-compatible bucket. The block is set when any field is; a set
// block is validated whenever the cache is enabled.
type RemoteCacheConfig struct {
	// Type selects the remote implementation. Only "s3" is supported, and
	// it is required.
	Type string `yaml:"type"`
	// Bucket is the bucket holding sealed entries. Required.
	Bucket string `yaml:"bucket"`
	// Prefix is the key prefix within Bucket; one prefix is one trust
	// domain. Empty, or ending with "/".
	Prefix string `yaml:"prefix"`
	// Region is the signing region, and selects the AWS regional endpoint
	// when Endpoint is empty. Required; it is never read from the
	// environment.
	Region string `yaml:"region"`
	// Endpoint is the service base URL of an S3-compatible store (R2,
	// Ceph, GCS interoperability, directory buckets, China partitions).
	// It must be https, or http for a loopback host. Empty selects
	// https://s3.<region>.amazonaws.com.
	Endpoint string `yaml:"endpoint"`
	// ForcePathStyle selects path-style bucket addressing.
	ForcePathStyle bool `yaml:"forcePathStyle"`
	// HeaderTimeout is a Go duration string bounding each remote request
	// except an upload: the response of an existence check, listing page
	// or deletion, the response headers of a read, and then the read of a
	// remote entry's sealed header before a fill falls through to
	// upstream. It also bounds the deletion of remote refs entries after
	// a push. "0s" removes the per-request bound: the sealed-header read is
	// then bounded by idleTimeout, and the deletions after a push, a failed
	// verification or a superseded upload by one minute. Defaults to "10s".
	HeaderTimeout string `yaml:"headerTimeout"`
	// SSE is the server-side encryption requested on upload: empty,
	// "AES256" or "aws:kms".
	SSE string `yaml:"sse"`
	// KMSKeyID names the KMS key when SSE is "aws:kms"; it is rejected
	// otherwise. Empty uses the bucket's default key.
	KMSKeyID string `yaml:"kmsKeyID"`

	parsedHeaderTimeout time.Duration
}

// HasRemote reports whether the block configures a remote tier.
func (c CacheConfig) HasRemote() bool { return c.Remote.set() }

// set reports whether any field of the block is set.
func (r RemoteCacheConfig) set() bool {
	r.parsedHeaderTimeout = 0
	return r != RemoteCacheConfig{}
}

// ParsedHeaderTimeout returns the time.Duration a prior successful call to
// Config.Validate parsed from HeaderTimeout. Zero means "no bound" (or
// that Validate has not run).
func (r RemoteCacheConfig) ParsedHeaderTimeout() time.Duration { return r.parsedHeaderTimeout }

// validate checks a set remote block structurally, without network or
// environment access.
func (r *RemoteCacheConfig) validate() error {
	switch r.Type {
	case remoteTypeS3:
	case "":
		return fmt.Errorf("cache.remote: type is required (want %q)", remoteTypeS3)
	default:
		return fmt.Errorf("cache.remote: type %q is not supported (want %q)", r.Type, remoteTypeS3)
	}
	if r.Bucket == "" {
		return errors.New("cache.remote: bucket is required")
	}
	if r.Prefix != "" && !strings.HasSuffix(r.Prefix, "/") {
		return fmt.Errorf("cache.remote: prefix %q must end with \"/\"", r.Prefix)
	}
	if r.Region == "" {
		return errors.New("cache.remote: region is required; it is never taken from AWS_REGION")
	}
	if r.Endpoint == "" {
		if err := s3store.ValidateDefaultRegion(r.Region); err != nil {
			return fmt.Errorf("cache.remote: %w", err)
		}
	} else if err := s3store.ValidateEndpoint(r.Endpoint); err != nil {
		return fmt.Errorf("cache.remote: %w", err)
	}
	switch r.SSE {
	case "", remoteSSEAES256, remoteSSEKMS:
	default:
		return fmt.Errorf("cache.remote: sse %q is not supported (want \"\", %q or %q)", r.SSE, remoteSSEAES256, remoteSSEKMS)
	}
	if r.KMSKeyID != "" && r.SSE != remoteSSEKMS {
		return fmt.Errorf("cache.remote: kmsKeyID requires sse %q", remoteSSEKMS)
	}
	if r.HeaderTimeout != "" {
		d, err := time.ParseDuration(r.HeaderTimeout)
		if err != nil {
			return fmt.Errorf("cache.remote: headerTimeout %q is not a valid duration: %w", r.HeaderTimeout, err)
		}
		if d < 0 {
			return fmt.Errorf("cache.remote: headerTimeout %q must not be negative", r.HeaderTimeout)
		}
		r.parsedHeaderTimeout = d
	}
	return nil
}

// storeConfig maps a validated block onto the s3 backend's configuration.
func (r RemoteCacheConfig) storeConfig() s3store.Config {
	return s3store.Config{
		Bucket:         r.Bucket,
		Prefix:         r.Prefix,
		Region:         r.Region,
		Endpoint:       r.Endpoint,
		ForcePathStyle: r.ForcePathStyle,
		HeaderTimeout:  r.parsedHeaderTimeout,
		SSE:            r.SSE,
		KMSKeyID:       r.KMSKeyID,
	}
}

// ParsedRetention returns the time.Duration a prior successful call to
// Config.Validate parsed from Retention. Zero when Validate has not run.
func (c CacheConfig) ParsedRetention() time.Duration { return c.parsedRetention }

// ParsedRefsMaxAge returns the time.Duration a prior successful call to
// Config.Validate parsed from RefsMaxAge. Zero means "always revalidate"
// (or that Validate has not run).
func (c CacheConfig) ParsedRefsMaxAge() time.Duration { return c.parsedRefsMaxAge }

// ParsedAccessRecheck returns the time.Duration a prior successful call
// to Config.Validate parsed from AccessRecheck. Zero when Validate has
// not run.
func (c CacheConfig) ParsedAccessRecheck() time.Duration { return c.parsedAccessRecheck }

// ParsedResponseHeaderTimeout returns the time.Duration a prior
// successful call to Config.Validate parsed from ResponseHeaderTimeout.
// Zero means "no bound" (or that Validate has not run).
func (c CacheConfig) ParsedResponseHeaderTimeout() time.Duration {
	return c.parsedResponseHeaderTimeout
}

// ParsedIdleTimeout returns the time.Duration a prior successful call to
// Config.Validate parsed from IdleTimeout. Zero means "no bound" (or that
// Validate has not run).
func (c CacheConfig) ParsedIdleTimeout() time.Duration { return c.parsedIdleTimeout }

// applyDefaults selects the default for every field of an enabled block
// that is unset: a size or count of zero and an empty duration string
// both mean unset. A disabled block is left untouched so it stays inert.
func (c *CacheConfig) applyDefaults() {
	if !c.Enabled {
		return
	}
	if c.MaxDiskSize == 0 {
		c.MaxDiskSize = defaultCacheMaxDiskSize
	}
	if c.MaxEntrySize == 0 {
		c.MaxEntrySize = defaultCacheMaxEntrySize
	}
	if c.MaxConcurrentFills == 0 {
		c.MaxConcurrentFills = defaultCacheMaxConcurrentFills
	}
	if c.MaxRequestBody == 0 {
		c.MaxRequestBody = defaultCacheMaxRequestBody
	}
	if c.Retention == "" {
		c.Retention = defaultCacheRetention
	}
	if c.RefsMaxAge == "" {
		c.RefsMaxAge = defaultCacheRefsMaxAge
	}
	if c.AccessRecheck == "" {
		c.AccessRecheck = defaultCacheAccessRecheck
	}
	if c.ResponseHeaderTimeout == "" {
		c.ResponseHeaderTimeout = defaultCacheResponseHeaderTimeout
	}
	if c.IdleTimeout == "" {
		c.IdleTimeout = defaultCacheIdleTimeout
	}
	if c.Remote.set() && c.Remote.HeaderTimeout == "" {
		c.Remote.HeaderTimeout = defaultRemoteHeaderTimeout
	}
}

// validate fail-fasts on an enabled block that is structurally unusable:
// a missing dir, a duration that does not parse or is negative, sizes or
// limits out of range, an invalid remote block or one without keyEnv, or
// a stale-if-error setting. It does
// no filesystem, network or environment access, so `haybale policy check`
// stays offline; the directory and key are checked when the cache is
// built. A disabled block is always valid. An empty duration is accepted
// as zero, as drainTimeout is, since applyDefaults only runs in Load.
func (c *CacheConfig) validate() error {
	if !c.Enabled {
		return nil
	}
	if c.Dir == "" {
		return fmt.Errorf("cache: dir is required when the cache is enabled")
	}

	durations := []struct {
		name string
		raw  string
		dst  *time.Duration
	}{
		{"retention", c.Retention, &c.parsedRetention},
		{"refsMaxAge", c.RefsMaxAge, &c.parsedRefsMaxAge},
		{"accessRecheck", c.AccessRecheck, &c.parsedAccessRecheck},
		{"responseHeaderTimeout", c.ResponseHeaderTimeout, &c.parsedResponseHeaderTimeout},
		{"idleTimeout", c.IdleTimeout, &c.parsedIdleTimeout},
	}
	for _, d := range durations {
		if d.raw == "" {
			continue
		}
		parsed, err := time.ParseDuration(d.raw)
		if err != nil {
			return fmt.Errorf("cache: %s %q is not a valid duration: %w", d.name, d.raw, err)
		}
		if parsed < 0 {
			return fmt.Errorf("cache: %s %q must not be negative", d.name, d.raw)
		}
		*d.dst = parsed
	}

	if c.Retention != "" && c.parsedRetention == 0 {
		// A zero retention would expire every entry at commit, making the
		// cache a pure spool that never serves a hit; "0s" here is far
		// more likely a mistake than an intent.
		return fmt.Errorf("cache: retention %q must be greater than zero", c.Retention)
	}
	if c.parsedRefsMaxAge > 0 && c.parsedAccessRecheck > 0 && c.parsedRefsMaxAge >= c.parsedAccessRecheck {
		return fmt.Errorf("cache: refsMaxAge %q must be less than accessRecheck %q: a refs response served from the cache does not renew the upstream access check cached packs depend on", c.RefsMaxAge, c.AccessRecheck)
	}
	if c.MaxEntrySize > c.MaxDiskSize/2 {
		return fmt.Errorf("cache: maxEntrySize %s must not exceed half of maxDiskSize %s", c.MaxEntrySize, c.MaxDiskSize)
	}
	if c.MaxConcurrentFills < 1 {
		return fmt.Errorf("cache: maxConcurrentFills must be at least 1, got %d", c.MaxConcurrentFills)
	}
	if c.MaxRequestBody <= 0 {
		return fmt.Errorf("cache: maxRequestBody must be greater than zero, got %s", c.MaxRequestBody)
	}

	if c.Remote.set() {
		if err := c.Remote.validate(); err != nil {
			return err
		}
		if c.KeyEnv == "" {
			return errors.New("cache: keyEnv is required when cache.remote is set, so that every replica seals and addresses entries under the same key")
		}
	}
	if c.StaleIfErrorFor != "" {
		d, err := time.ParseDuration(c.StaleIfErrorFor)
		if err != nil || d != 0 {
			return fmt.Errorf("cache: staleIfErrorFor is not supported in this release (got %q); leave it empty or \"0s\"", c.StaleIfErrorFor)
		}
	}
	return nil
}

// LoadKeyring builds the Keyring from the environment variable named by
// KeyEnv, which must hold a base64-encoded 32-byte key. Errors name the
// variable and never include its value. KeyEnv must be set; BuildCache
// generates an ephemeral key itself when it is not.
func (c CacheConfig) LoadKeyring() (cache.Keyring, error) {
	raw, ok := os.LookupEnv(c.KeyEnv)
	if !ok || raw == "" {
		return cache.Keyring{}, fmt.Errorf("cache: environment variable %q (keyEnv) is unset or empty", c.KeyEnv)
	}
	key, err := cache.Decode32(raw)
	if err != nil {
		return cache.Keyring{}, fmt.Errorf("cache: environment variable %q (keyEnv): %w", c.KeyEnv, err)
	}
	return cache.NewKeyring(key)
}

// maxAliasDepth bounds how many alias hops resolveAlias follows.
const maxAliasDepth = 32

// resolveAlias follows alias nodes to the node they refer to. A chain
// longer than maxAliasDepth, which only a cycle can produce, is returned
// still unresolved, so it is not a mapping and the decoder rejects it.
func resolveAlias(node *yaml.Node) *yaml.Node {
	for range maxAliasDepth {
		if node == nil || node.Kind != yaml.AliasNode {
			return node
		}
		node = node.Alias
	}
	return node
}

// validateCacheKeys rejects unknown keys in the cache block of a parsed
// YAML document, whether the block is written inline or reached through
// an alias. The rest of the file tolerates unknown keys, but a mistyped
// or renamed cache key would otherwise silently revert to its default.
// doc is the document node Load parsed; a file without a cache block is
// valid.
func validateCacheKeys(doc *yaml.Node) error {
	if doc.Kind == yaml.DocumentNode && len(doc.Content) > 0 {
		doc = doc.Content[0]
	}
	block := mappingValue(doc, "cache")
	if block == nil {
		return nil
	}
	if err := checkKnownKeys(block, reflect.TypeFor[CacheConfig](), "cache"); err != nil {
		return err
	}
	if remote := mappingValue(block, "remote"); remote != nil {
		return checkKnownKeys(remote, reflect.TypeFor[RemoteCacheConfig](), "cache.remote")
	}
	return nil
}

// mappingValue returns the value node for key in a mapping node, or nil
// when node is not a mapping or has no such key. Aliases are resolved on
// the node, on each key and on the returned value.
func mappingValue(node *yaml.Node, key string) *yaml.Node {
	node = resolveAlias(node)
	if node == nil || node.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(node.Content); i += 2 {
		if resolveAlias(node.Content[i]).Value == key {
			return resolveAlias(node.Content[i+1])
		}
	}
	return nil
}

// checkKnownKeys requires every key of the mapping node to name a yaml
// field of typ. prefix is the block's name for the error. A node that is
// not a mapping after alias resolution is left to the decoder.
func checkKnownKeys(node *yaml.Node, typ reflect.Type, prefix string) error {
	node = resolveAlias(node)
	if node == nil || node.Kind != yaml.MappingNode {
		return nil
	}
	known := make(map[string]bool, typ.NumField())
	for i := range typ.NumField() {
		if tag, _, _ := strings.Cut(typ.Field(i).Tag.Get("yaml"), ","); tag != "" && tag != "-" {
			known[tag] = true
		}
	}
	for i := 0; i+1 < len(node.Content); i += 2 {
		if key := node.Content[i]; !known[resolveAlias(key).Value] {
			return fmt.Errorf("%s: unknown field %q (line %d)", prefix, resolveAlias(key).Value, key.Line)
		}
	}
	return nil
}

// BuildRemote constructs the remote tier a validated, enabled block
// describes, or returns nil when the block has none. It sends no request;
// ctx bounds loading the AWS SDK's shared configuration. Credentials come
// from the SDK's default chain.
func (c CacheConfig) BuildRemote(ctx context.Context) (cache.BlobStore, error) {
	if !c.Enabled || !c.Remote.set() {
		return nil, nil
	}
	store, err := s3store.New(ctx, c.Remote.storeConfig())
	if err != nil {
		return nil, fmt.Errorf("cache.remote: %w", err)
	}
	return store, nil
}

// errProbeKeyFound reports a probe GET that succeeded. The key is random
// and never written, so the endpoint is not behaving as S3.
var errProbeKeyFound = errors.New("cache.remote: the startup probe read a random key under " + remoteProbePrefix +
	", which haybale never writes, so the endpoint is not behaving as S3-compatible storage")

// newProbeKey returns a fresh random key under remoteProbePrefix.
func newProbeKey() string {
	var b [16]byte
	_, _ = rand.Read(b[:]) // crypto/rand.Read never returns an error
	return remoteProbePrefix + hex.EncodeToString(b[:])
}

// probeRemote reads a new random key under remoteProbePrefix to check
// that the remote tier is usable. Not found is healthy. A failure that will not resolve itself
// fails startup: missing credentials, a certificate that does not verify,
// a redirect, or any 4xx other than 408 and 429, such as AccessDenied,
// NoSuchBucket or ExpiredToken. A probe GET that succeeds fails startup
// too. Any other failure, such as a network error, a timeout, a 5xx or
// throttling, is logged and startup continues, so a bucket outage cannot
// stop haybale from starting. The probe uses a GET rather than a HEAD
// because a HEAD response has no body to tell a missing bucket from a
// missing object.
func probeRemote(ctx context.Context, store cache.BlobStore, logger *slog.Logger) error {
	ctx, cancel := context.WithTimeout(ctx, remoteProbeTimeout)
	defer cancel()
	rc, _, err := store.Get(ctx, newProbeKey(), 0)
	switch {
	case err == nil:
		_ = rc.Close()
		return errProbeKeyFound
	case errors.Is(err, cache.ErrNotFound):
		return nil
	}
	var se *s3store.Error
	switch {
	case errors.As(err, &se) && se.Code == "NoCredentials":
		return fmt.Errorf("cache.remote: no AWS credentials were found in the SDK's default chain; "+
			"configure IRSA, EKS Pod Identity, AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY, or a shared profile: %w", err)
	case errors.As(err, &se) && remotePermanentError(se):
		return fmt.Errorf("cache.remote: the bucket cannot be used with these credentials and settings: %w", err)
	}
	logger.Warn("cache.remote: the startup probe of the bucket failed; continuing, and remote operations retry on use", "error", err)
	return nil
}

// remotePermanentError reports whether a probe failure is a credential,
// TLS, authorization or bucket configuration error that retrying will not
// fix.
func remotePermanentError(e *s3store.Error) bool {
	switch e.Code {
	case "AccessDenied", "InvalidAccessKeyId", "SignatureDoesNotMatch", "NoSuchBucket",
		"PermanentRedirect", "AuthorizationHeaderMalformed", "ExpiredToken", "InvalidToken",
		"NoCredentials", "TLSVerificationFailed":
		return true
	}
	switch e.Status {
	case http.StatusRequestTimeout, http.StatusTooManyRequests:
		return false
	}
	return e.Status >= 300 && e.Status < 500
}

// BuildCache constructs the live response cache from a validated block:
// it reads the key from the environment variable named by KeyEnv, or
// generates an ephemeral key when KeyEnv is empty, opens the cache
// directory, constructs and probes the remote tier when one is
// configured, and starts the janitor and upload workers. It returns nil,
// nil when the cache is disabled. It must be called after Validate and
// only by `haybale serve`; it is deliberately separate from validate so
// the offline `haybale policy check` never touches the directory, the
// environment or the network. The caller closes the returned cache after
// draining in-flight requests.
func (c CacheConfig) BuildCache(ctx context.Context, logger *slog.Logger, metrics *observability.Metrics) (*cache.Cache, error) {
	if !c.Enabled {
		return nil, nil
	}
	var keyring cache.Keyring
	keyMode := "configured"
	if c.KeyEnv != "" {
		var err error
		if keyring, err = c.LoadKeyring(); err != nil {
			return nil, err
		}
	} else {
		var err error
		keyring, err = cache.EphemeralKeyring()
		if err != nil {
			return nil, err
		}
		logger.Info("keyEnv is not set; entries are sealed under an ephemeral key, the cache does not survive a restart, and its entries are removed at the next start")
		keyMode = "ephemeral"
	}
	remote, err := c.BuildRemote(ctx)
	if err != nil {
		return nil, err
	}
	if remote != nil {
		if err := probeRemote(ctx, remote, logger); err != nil {
			return nil, err
		}
	}
	built, err := cache.New(cache.Options{
		Dir:                   c.Dir,
		Keyring:               keyring,
		MaxDiskSize:           int64(c.MaxDiskSize),
		MaxEntrySize:          int64(c.MaxEntrySize),
		MaxConcurrentFills:    c.MaxConcurrentFills,
		MaxRequestBody:        int64(c.MaxRequestBody),
		Retention:             c.parsedRetention,
		RefsMaxAge:            c.parsedRefsMaxAge,
		AccessRecheck:         c.parsedAccessRecheck,
		ResponseHeaderTimeout: c.parsedResponseHeaderTimeout,
		IdleTimeout:           c.parsedIdleTimeout,
		ExposeStatus:          c.ExposeStatus,
		Remote:                remote,
		RemoteHeaderTimeout:   c.Remote.parsedHeaderTimeout,
		Logger:                logger,
		Metrics:               metrics,
	})
	if err != nil {
		return nil, err
	}
	if int64(c.MaxConcurrentFills) > int64(c.MaxDiskSize)/int64(c.MaxEntrySize) {
		logger.Warn("concurrent fills can reserve more than the disk budget",
			"maxConcurrentFills", c.MaxConcurrentFills,
			"maxEntrySize", c.MaxEntrySize.String(),
			"maxDiskSize", c.MaxDiskSize.String())
	}
	logger.Info("response cache enabled",
		"dir", c.Dir,
		"keyMode", keyMode,
		"maxDiskSize", c.MaxDiskSize.String(),
		"maxEntrySize", c.MaxEntrySize.String(),
		"maxConcurrentFills", c.MaxConcurrentFills)
	if remote != nil {
		logger.Info("response cache remote tier enabled",
			"type", c.Remote.Type,
			"bucket", c.Remote.Bucket,
			"prefix", c.Remote.Prefix,
			"region", c.Remote.Region,
			"endpoint", c.Remote.Endpoint)
	}
	return built, nil
}
