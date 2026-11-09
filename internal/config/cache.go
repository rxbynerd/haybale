package config

import (
	"fmt"
	"math/big"
	"regexp"
	"time"

	"gopkg.in/yaml.v3"
)

// Defaults applied to an enabled CacheConfig by applyDefaults. A disabled
// block receives none of them and stays inert.
const (
	defaultCacheMaxDiskSize           = 10 * gib
	defaultCacheMaxEntrySize          = 1 * gib
	defaultCacheMaxConcurrentFills    = 32
	defaultCacheMaxRequestBody        = 1 * mib
	defaultCacheRetention             = "24h"
	defaultCacheRefsMaxAge            = "0s"
	defaultCacheAccessRecheck         = "5m"
	defaultCacheResponseHeaderTimeout = "0s"
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
// example "512MiB" or "1.5GiB"). A bare integer, an SI unit (KB, MB, GB),
// a negative value or any other form is rejected, so a configured size
// can never be misread by a factor of 1024 or silently taken as bytes.
type ByteSize int64

// UnmarshalYAML parses a scalar node into a ByteSize. A number that does
// not resolve to a whole number of bytes (for example "1.0001KiB") or
// that overflows int64 is rejected. Errors name the YAML line because
// the decoder does not report which field held the value.
func (b *ByteSize) UnmarshalYAML(value *yaml.Node) error {
	if value.Kind != yaml.ScalarNode {
		return fmt.Errorf("line %d: size must be a string such as \"10GiB\"", value.Line)
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
	// required when Enabled and must be private to the haybale process
	// (mode 0700); that is checked when the directory is opened, not by
	// validate.
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
	// stream through unstored. It must not exceed MaxDiskSize. Defaults
	// to 1GiB.
	MaxEntrySize ByteSize `yaml:"maxEntrySize"`
	// MaxConcurrentFills bounds simultaneous cache fills. Must be at
	// least 1. Defaults to 32.
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
	AccessRecheck string `yaml:"accessRecheck"`
	// ResponseHeaderTimeout is a Go duration string bounding how long the
	// cache's upstream fetches wait for response headers. "0s" (the
	// default) applies no bound.
	ResponseHeaderTimeout string `yaml:"responseHeaderTimeout"`
	// ExposeStatus makes haybale emit a Cache-Status response header.
	// Defaults to false.
	ExposeStatus bool `yaml:"exposeStatus"`
	// Remote configures a shared remote tier. It is reserved for a later
	// release: any non-zero value fails validate.
	Remote RemoteCacheConfig `yaml:"remote"`
	// StaleIfErrorFor is a Go duration string: the maximum age of an
	// entry served when upstream cannot answer. It is reserved for a
	// later release: only empty or "0s" is accepted.
	StaleIfErrorFor string `yaml:"staleIfErrorFor"`

	// The parsed* fields cache the durations validate parsed, for the
	// same reuse-not-reparse reason Config.parsedDrainTimeout exists.
	parsedRetention             time.Duration
	parsedRefsMaxAge            time.Duration
	parsedAccessRecheck         time.Duration
	parsedResponseHeaderTimeout time.Duration
}

// RemoteCacheConfig configures the optional shared remote cache tier,
// an object-storage bucket. It is reserved for a later release and is
// rejected by CacheConfig.validate when any field is set.
type RemoteCacheConfig struct {
	// Type selects the remote implementation, e.g. "s3".
	Type string `yaml:"type"`
	// Bucket is the bucket holding sealed entries.
	Bucket string `yaml:"bucket"`
	// Prefix is the key prefix within Bucket; one prefix is one trust
	// domain.
	Prefix string `yaml:"prefix"`
	// Region is the bucket's region.
	Region string `yaml:"region"`
	// Endpoint overrides the service endpoint (https), for S3-compatible
	// stores.
	Endpoint string `yaml:"endpoint"`
	// ForcePathStyle selects path-style bucket addressing.
	ForcePathStyle bool `yaml:"forcePathStyle"`
	// Timeout is a Go duration string bounding each remote operation on
	// the request path.
	Timeout string `yaml:"timeout"`
	// SSE is the server-side encryption mode, "AES256" or "aws:kms".
	SSE string `yaml:"sse"`
	// KMSKeyID names the KMS key when SSE is "aws:kms".
	KMSKeyID string `yaml:"kmsKeyID"`
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

// applyDefaults fills in every unset field of an enabled block. A
// disabled block is left untouched so it stays inert.
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
}

// validate fail-fasts on an enabled block that is structurally unusable:
// a missing dir, a duration that does not parse or is negative, sizes or
// limits out of range, or a field reserved for a later release. It does
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
	if c.MaxEntrySize > c.MaxDiskSize {
		return fmt.Errorf("cache: maxEntrySize %s must not exceed maxDiskSize %s", c.MaxEntrySize, c.MaxDiskSize)
	}
	if c.MaxConcurrentFills < 1 {
		return fmt.Errorf("cache: maxConcurrentFills must be at least 1, got %d", c.MaxConcurrentFills)
	}
	if c.MaxRequestBody <= 0 {
		return fmt.Errorf("cache: maxRequestBody must be greater than zero, got %s", c.MaxRequestBody)
	}

	if c.Remote != (RemoteCacheConfig{}) {
		return fmt.Errorf("cache: cache.remote is not supported in this release; remove the remote block")
	}
	if c.StaleIfErrorFor != "" && c.StaleIfErrorFor != "0s" {
		return fmt.Errorf("cache: cache.staleIfErrorFor is not supported in this release (got %q); leave it empty or \"0s\"", c.StaleIfErrorFor)
	}
	return nil
}
