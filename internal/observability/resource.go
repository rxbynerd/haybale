// Package observability wires haybale's OpenTelemetry pipeline: traces,
// metrics, and logs exported over OTLP to a collector. It is the haybale
// counterpart of Stirrup's harness/internal/observability package and
// follows the same conventions (one shared Resource across all three
// signals, OTLP over gRPC or HTTP/protobuf, env-var fallbacks for
// low-cardinality resource labels), adapted for a long-lived server rather
// than a per-run CLI: Setup runs once at startup and Providers.Shutdown
// runs once during graceful drain.
//
// Everything here degrades to a no-op when telemetry is not configured (an
// empty Config.Endpoint): the metric instruments fall back to
// noop.MeterProvider, no exporters are created, no OTLP connection is
// dialled, and the global TracerProvider stays the SDK's default no-op. A
// deployment that leaves the telemetry block out of its YAML pays nothing.
package observability

import (
	"crypto/rand"
	"encoding/hex"
	"os"
	"regexp"
	"sync"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/sdk/resource"
	semconv "go.opentelemetry.io/otel/semconv/v1.34.0"
)

// ServiceName is the value emitted as service.name on every span, metric,
// and log record. It is the canonical identifier haybale presents to
// OTel-aware backends (Tempo, Jaeger, Mimir, Honeycomb, Datadog, etc.).
const ServiceName = "haybale"

// DefaultServiceNamespace is emitted as service.namespace when no
// operator-supplied or env-var value is available. It matches ServiceName
// so a default deployment still groups under a sensible namespace label
// rather than leaving the attribute unset (which makes a backend's
// group-by quietly drop rows). Mirrors Stirrup's DefaultServiceNamespace
// = "stirrup" so both Equestrianism services follow the same convention.
const DefaultServiceNamespace = "haybale"

// DefaultEnvironment is emitted as deployment.environment when no
// operator-supplied or env-var value is available. "local" matches the
// convention used by the OTel demo and Grafana sample dashboards, so the
// out-of-the-box experience hits the right tile rather than a fallback
// bucket.
const DefaultEnvironment = "local"

// envEnvironment / envServiceNamespace are the env-var fallbacks consulted
// when a Config value is empty. These are haybale-specific env vars — they
// are not part of the OTel SDK specification — and share the OTEL_ prefix
// for discoverability alongside the SDK's own OTEL_RESOURCE_ATTRIBUTES.
// They match the names Stirrup reads so a fleet running both services can
// set one pair of env vars.
const (
	envEnvironment      = "OTEL_DEPLOYMENT_ENVIRONMENT"
	envServiceNamespace = "OTEL_SERVICE_NAMESPACE"
)

// labelPattern bounds an operator-supplied or env-var resource label to a
// short, safe character set. Without it, a hostile or fat-fingered
// OTEL_DEPLOYMENT_ENVIRONMENT (an embedded newline, > 64 bytes, an `=`
// that would corrupt OTEL_RESOURCE_ATTRIBUTES-style parsing downstream)
// would propagate verbatim onto every exported span, metric, and log
// batch. Mirrors Stirrup's observabilityLabelPattern.
var labelPattern = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)

var (
	instanceIDOnce sync.Once
	instanceID     string
)

// InstanceID returns a stable random identifier for the current process,
// generated once at first call and reused for the process's lifetime. It
// is emitted as service.instance.id so concurrent haybale processes
// (behind a load balancer, or during a rolling deploy) can be
// distinguished in an OTel-aware backend.
//
// 16 bytes (128 bits) of randomness makes collisions across every running
// haybale process vanishingly unlikely. The "unknown" fallback is only
// reached if crypto/rand.Read fails, which on a Unix host implies
// /dev/urandom is unreadable — an environment haybale cannot meaningfully
// run in anyway.
func InstanceID() string {
	instanceIDOnce.Do(func() {
		var b [16]byte
		if _, err := rand.Read(b[:]); err != nil {
			instanceID = "unknown"
			return
		}
		instanceID = hex.EncodeToString(b[:])
	})
	return instanceID
}

// ResourceOptions carries the low-cardinality attributes that ride on the
// OTel Resource shared by all three signals. Only low-cardinality labels
// belong here: putting a per-request value (repo owner/name, identity) on
// the resource would explode metric-series cardinality on a backend like
// Mimir, so those are emitted at the span / instrument level instead.
//
// Empty Environment / ServiceNamespace fall through to the
// OTEL_DEPLOYMENT_ENVIRONMENT / OTEL_SERVICE_NAMESPACE env vars and then
// to the documented defaults. Version is haybale's build version (the
// cmd-package `version` var), threaded in rather than imported to avoid an
// import cycle (cmd imports this package).
type ResourceOptions struct {
	Environment      string
	ServiceNamespace string
	Version          string
}

// BuildResource builds the OTel Resource identifying this haybale process.
//
// It merges two sources, later winning on key conflicts:
//  1. resource.Default() — telemetry.sdk.{name,language,version},
//     host.name, and any operator-supplied OTEL_RESOURCE_ATTRIBUTES.
//     resource.Default() also seeds service.name as
//     "unknown_service:<binary>"; the overlay below replaces it.
//  2. haybale's service identity — service.name, service.version,
//     service.instance.id, service.namespace, deployment.environment.
//
// The Default resource's SchemaURL is reused for the overlay so
// resource.Merge always succeeds; if it nonetheless fails (a future SDK
// changing the merge contract), a schemaless resource carrying just the
// haybale attributes is returned, which still fixes the
// "unknown_service:haybale" default that is the user-visible problem.
//
// The deployment-environment key is the legacy stable "deployment.environment"
// rather than semconv v1.34.0's newer "deployment.environment.name": the
// legacy key is what existing Grafana dashboards and collector processors
// look for, so emitting the .name suffix would silently break operator
// dashboards. This mirrors the identical decision documented in Stirrup's
// BuildResource.
func BuildResource(opts ResourceOptions) *resource.Resource {
	env := sanitiseLabel(firstNonEmpty(opts.Environment, os.Getenv(envEnvironment)), DefaultEnvironment)
	ns := sanitiseLabel(firstNonEmpty(opts.ServiceNamespace, os.Getenv(envServiceNamespace)), DefaultServiceNamespace)

	version := opts.Version
	if version == "" {
		version = "dev"
	}

	attrs := []attribute.KeyValue{
		semconv.ServiceName(ServiceName),
		semconv.ServiceVersion(version),
		semconv.ServiceInstanceID(InstanceID()),
		semconv.ServiceNamespace(ns),
		// See the doc comment above for why this is the legacy
		// "deployment.environment" key rather than semconv's newer
		// DeploymentEnvironmentName.
		attribute.String("deployment.environment", env),
	}

	base := resource.Default()
	overlay := resource.NewWithAttributes(base.SchemaURL(), attrs...)
	merged, err := resource.Merge(base, overlay)
	if err != nil {
		return resource.NewSchemaless(attrs...)
	}
	return merged
}

// firstNonEmpty returns the first non-empty argument, or "" if all are
// empty — the explicit -> env -> default precedence chain in one line.
func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

// sanitiseLabel returns v when it matches labelPattern, otherwise
// fallback. An empty v also resolves to fallback, so callers use it as a
// single "first valid label, else default" reducer. See labelPattern's
// doc comment for why an unvalidated env-var value must never reach an
// exported batch.
func sanitiseLabel(v, fallback string) string {
	if v == "" {
		return fallback
	}
	if labelPattern.MatchString(v) {
		return v
	}
	return fallback
}
