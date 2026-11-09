package s3store

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// Server-side encryption modes Config.SSE accepts.
const (
	sseS3  = "AES256"
	sseKMS = "aws:kms"
)

// awsRegionPattern bounds the region spliced into the default AWS
// endpoint host, so a region value can never change the host's domain.
var awsRegionPattern = regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)*$`)

// Config describes one S3-compatible bucket prefix.
type Config struct {
	// Bucket is the bucket holding the objects. Required.
	Bucket string
	// Prefix is prepended to every object key. It is empty or ends with
	// "/".
	Prefix string
	// Region is the signing region, and selects the AWS regional
	// endpoint when Endpoint is empty. Required.
	Region string
	// Endpoint is the service base URL for an S3-compatible store. It
	// must be https, or http for a loopback host. Empty selects
	// https://s3.<Region>.amazonaws.com.
	Endpoint string
	// ForcePathStyle addresses the bucket in the URL path instead of the
	// host name.
	ForcePathStyle bool
	// HeaderTimeout bounds how long Stat, Delete and each List page wait
	// for their response, and Get for its response headers; it does not
	// bound reading a Get body or a Put. Zero leaves only the caller's
	// context.
	HeaderTimeout time.Duration
	// SSE is the server-side encryption mode requested on upload: empty,
	// "AES256" or "aws:kms".
	SSE string
	// KMSKeyID names the KMS key when SSE is "aws:kms". Empty uses the
	// bucket's default key.
	KMSKeyID string
}

// validate checks c and returns the base endpoint the client must use.
func (c Config) validate() (string, error) {
	if c.Bucket == "" {
		return "", errors.New("s3store: bucket is required")
	}
	if c.Prefix != "" && !strings.HasSuffix(c.Prefix, "/") {
		return "", fmt.Errorf("s3store: prefix %q must end with \"/\"", c.Prefix)
	}
	if c.Region == "" {
		return "", errors.New("s3store: region is required")
	}
	if c.HeaderTimeout < 0 {
		return "", fmt.Errorf("s3store: header timeout %s must not be negative", c.HeaderTimeout)
	}
	switch c.SSE {
	case "", sseS3, sseKMS:
	default:
		return "", fmt.Errorf("s3store: sse %q is not %q or %q", c.SSE, sseS3, sseKMS)
	}
	if c.KMSKeyID != "" && c.SSE != sseKMS {
		return "", fmt.Errorf("s3store: a KMS key id requires sse %q", sseKMS)
	}
	if c.Endpoint == "" {
		if err := ValidateDefaultRegion(c.Region); err != nil {
			return "", fmt.Errorf("s3store: %w", err)
		}
		return "https://s3." + c.Region + ".amazonaws.com", nil
	}
	if err := ValidateEndpoint(c.Endpoint); err != nil {
		return "", fmt.Errorf("s3store: %w", err)
	}
	return c.Endpoint, nil
}

// ValidateDefaultRegion reports whether region can be spliced into the
// default AWS endpoint host, which is used when no endpoint is set.
func ValidateDefaultRegion(region string) error {
	if !awsRegionPattern.MatchString(region) {
		return fmt.Errorf("region %q is not a valid AWS region name", region)
	}
	return nil
}

// ValidateEndpoint requires an absolute https URL, or http for a loopback
// host, with no credentials, query or fragment. Its errors show the URL
// with any password redacted.
func ValidateEndpoint(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return errors.New("endpoint is not a valid URL")
	}
	shown := u.Redacted()
	switch {
	case u.User != nil || u.RawQuery != "" || u.Fragment != "":
		return fmt.Errorf("endpoint %q must not carry userinfo, a query or a fragment", shown)
	case u.Host == "":
		return fmt.Errorf("endpoint %q must be an absolute URL with a host", shown)
	case u.Scheme == "https":
		return nil
	case u.Scheme == "http" && isLoopbackHost(u.Hostname()):
		return nil
	default:
		return fmt.Errorf("endpoint %q must use https (http is permitted only for a loopback host)", shown)
	}
}

// isLoopbackHost reports whether host is localhost or a loopback IP
// literal (127.0.0.0/8, ::1).
func isLoopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	return false
}
