package observability

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"go.opentelemetry.io/contrib/bridges/otelslog"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploggrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploghttp"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/propagation"
	sdklog "go.opentelemetry.io/otel/sdk/log"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
)

// ScopeName is the instrumentation scope name carried on every span,
// metric, and log record haybale emits. A single shared scope across all
// three signals lets a backend attribute them to one instrumentation
// source, the same way Stirrup uses one "stirrup-harness" scope.
const ScopeName = "github.com/rxbynerd/haybale"

// ProtocolGRPC and ProtocolHTTP are the two OTLP wire protocols Setup
// accepts. An empty Config.Protocol is treated as ProtocolGRPC.
const (
	ProtocolGRPC = "grpc"
	ProtocolHTTP = "http/protobuf"
)

// Config is the resolved, plaintext telemetry configuration Setup
// consumes. It is deliberately a plain value struct with no YAML tags and
// no dependency on internal/config: cmd/haybale/cmd/serve.go translates
// the operator-facing config.TelemetryConfig into this, resolving any
// secret header material (from the environment) before it reaches here, so
// this package never touches the config file or an env-var-name
// indirection itself.
//
// An empty Endpoint means telemetry is disabled: Setup returns a no-op
// Providers and dials nothing.
type Config struct {
	// Endpoint is the OTLP collector endpoint. For grpc it is a host:port
	// (e.g. "localhost:4317") or an explicit "http://"/"https://" URL; for
	// http/protobuf it is a base URL (e.g.
	// "https://otlp.example.com/otlp"). Empty disables telemetry.
	Endpoint string
	// Protocol selects the OTLP wire protocol: "grpc" (default) or
	// "http/protobuf".
	Protocol string
	// Headers is forwarded to every OTLP exporter transport unchanged,
	// typically an Authorization bearer token for a managed collector.
	// Values are already-resolved plaintext — serve.go reads them from the
	// environment, never from the YAML file, matching haybale's invariant
	// that a secret is never written inline in config.
	Headers map[string]string
	// Resource carries the low-cardinality resource labels
	// (deployment.environment, service.namespace) and the build version.
	Resource ResourceOptions
}

// Enabled reports whether the config turns telemetry on at all.
func (c Config) Enabled() bool { return c.Endpoint != "" }

// Validate checks the telemetry config in isolation, without dialling
// anything, so a misconfigured protocol fails fast at startup (from
// config.Validate) rather than on the first export attempt. A disabled
// config (empty Endpoint) is always valid.
func (c Config) Validate() error {
	if !c.Enabled() {
		return nil
	}
	switch c.Protocol {
	case "", ProtocolGRPC, ProtocolHTTP:
	default:
		return fmt.Errorf("protocol %q is not supported (must be %q or %q)", c.Protocol, ProtocolGRPC, ProtocolHTTP)
	}
	return nil
}

// Providers owns the OTel SDK pipelines Setup built and is responsible for
// flushing and shutting them down. A no-op Providers (from a disabled
// Config) carries a noop-backed Metrics, a nil LogHandler, and a Shutdown
// that does nothing — so callers wire it unconditionally and never
// nil-check.
type Providers struct {
	tracerProvider *sdktrace.TracerProvider
	loggerProvider *sdklog.LoggerProvider

	// Metrics is always non-nil: a disabled Providers carries
	// noop-backed instruments so every call site records unconditionally.
	Metrics *Metrics

	// LogHandler is the leaf slog.Handler that ships each record to the
	// OTLP logs pipeline, or nil when telemetry is disabled. serve.go
	// composes it behind haybale's existing ScrubHandler so the OTLP path
	// is scrubbed identically to the stderr path — no log value leaves the
	// process unscrubbed regardless of sink.
	LogHandler slog.Handler
}

// Setup builds the trace, metric, and log pipelines cfg describes, sets
// the global TracerProvider and text-map propagator (so otel.Tracer and
// otelhttp instrumentation across the codebase resolve to the real
// pipeline with no further plumbing), and returns a Providers the caller
// shuts down at drain.
//
// When cfg is disabled (empty Endpoint), Setup returns a no-op Providers
// immediately: noop-backed Metrics, nil LogHandler, and the global
// TracerProvider left at the SDK's default no-op. No exporter is created
// and no OTLP connection is dialled.
//
// The metric pipeline is set as the global MeterProvider too, so
// otelhttp's own HTTP-server instrumentation records into the same
// pipeline as haybale's domain metrics. Traces use the global
// TracerProvider (idiomatic for a server; otelhttp reads it by default),
// while metrics are additionally handed to callers as a typed *Metrics for
// compile-checked, low-cardinality domain instruments.
func Setup(ctx context.Context, cfg Config) (*Providers, error) {
	if !cfg.Enabled() {
		return &Providers{Metrics: NewNoopMetrics()}, nil
	}

	res := BuildResource(cfg.Resource)

	traceExporter, err := buildTraceExporter(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("build trace exporter: %w", err)
	}
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(traceExporter),
		sdktrace.WithResource(res),
	)

	metrics, err := NewMetrics(ctx, cfg, res)
	if err != nil {
		// Undo the trace pipeline we already started before failing, so a
		// half-built Setup never leaks a live exporter/batcher goroutine.
		_ = tp.Shutdown(ctx)
		return nil, fmt.Errorf("build metrics: %w", err)
	}

	logExporter, err := buildLogExporter(ctx, cfg)
	if err != nil {
		_ = tp.Shutdown(ctx)
		_ = metrics.shutdown(ctx)
		return nil, fmt.Errorf("build log exporter: %w", err)
	}
	lp := sdklog.NewLoggerProvider(
		sdklog.WithProcessor(sdklog.NewBatchProcessor(logExporter)),
		sdklog.WithResource(res),
	)
	logHandler := otelslog.NewHandler(ScopeName, otelslog.WithLoggerProvider(lp))

	// Set globals last, once every pipeline built cleanly: otelhttp and
	// any otel.Tracer(ScopeName) call site resolves through these. The
	// propagator is W3C Trace Context + Baggage, the ecosystem default, so
	// haybale both continues an inbound trace and propagates one to the
	// upstream leg.
	otel.SetTracerProvider(tp)
	otel.SetMeterProvider(metrics.provider)
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))

	return &Providers{
		tracerProvider: tp,
		loggerProvider: lp,
		Metrics:        metrics,
		LogHandler:     logHandler,
	}, nil
}

// Shutdown flushes and shuts down every pipeline, returning the joined
// error of all three so one failing signal does not hide another. Safe to
// call on a no-op Providers (from a disabled Config) and on a nil
// receiver, so serve.go can defer it unconditionally. Give it a bounded
// context: a collector that has gone away must not make drain hang.
func (p *Providers) Shutdown(ctx context.Context) error {
	if p == nil {
		return nil
	}
	var errs []error
	if p.tracerProvider != nil {
		errs = append(errs, p.tracerProvider.Shutdown(ctx))
	}
	if p.Metrics != nil {
		errs = append(errs, p.Metrics.shutdown(ctx))
	}
	if p.loggerProvider != nil {
		errs = append(errs, p.loggerProvider.Shutdown(ctx))
	}
	return errors.Join(errs...)
}

// buildTraceExporter dispatches on the configured wire protocol and
// returns the matching OTLP trace exporter. Mirrors buildMetricExporter
// and buildLogExporter so all three signals dial a collector identically.
func buildTraceExporter(ctx context.Context, cfg Config) (*otlptrace.Exporter, error) {
	switch cfg.Protocol {
	case "", ProtocolGRPC:
		opts := []otlptracegrpc.Option{otlptracegrpc.WithEndpoint(stripURLScheme(cfg.Endpoint))}
		if isInsecureEndpoint(cfg.Endpoint) {
			opts = append(opts, otlptracegrpc.WithInsecure())
		}
		if len(cfg.Headers) > 0 {
			opts = append(opts, otlptracegrpc.WithHeaders(cfg.Headers))
		}
		return otlptracegrpc.New(ctx, opts...)
	case ProtocolHTTP:
		opts := []otlptracehttp.Option{otlptracehttp.WithEndpoint(stripURLScheme(cfg.Endpoint))}
		if path := urlPath(cfg.Endpoint); path != "" {
			opts = append(opts, otlptracehttp.WithURLPath(joinSignalPath(path, "traces")))
		}
		if isInsecureEndpoint(cfg.Endpoint) {
			opts = append(opts, otlptracehttp.WithInsecure())
		}
		if len(cfg.Headers) > 0 {
			opts = append(opts, otlptracehttp.WithHeaders(cfg.Headers))
		}
		return otlptracehttp.New(ctx, opts...)
	default:
		return nil, fmt.Errorf("unsupported OTLP protocol %q", cfg.Protocol)
	}
}

// buildLogExporter constructs the OTLP log exporter for the configured
// wire protocol, mirroring the trace and metric builders so an operator
// who sets protocol=http/protobuf gets identical routing for all three
// signals.
func buildLogExporter(ctx context.Context, cfg Config) (sdklog.Exporter, error) {
	switch cfg.Protocol {
	case "", ProtocolGRPC:
		opts := []otlploggrpc.Option{otlploggrpc.WithEndpoint(stripURLScheme(cfg.Endpoint))}
		if isInsecureEndpoint(cfg.Endpoint) {
			opts = append(opts, otlploggrpc.WithInsecure())
		}
		if len(cfg.Headers) > 0 {
			opts = append(opts, otlploggrpc.WithHeaders(cfg.Headers))
		}
		return otlploggrpc.New(ctx, opts...)
	case ProtocolHTTP:
		opts := []otlploghttp.Option{otlploghttp.WithEndpoint(stripURLScheme(cfg.Endpoint))}
		if path := urlPath(cfg.Endpoint); path != "" {
			opts = append(opts, otlploghttp.WithURLPath(joinSignalPath(path, "logs")))
		}
		if isInsecureEndpoint(cfg.Endpoint) {
			opts = append(opts, otlploghttp.WithInsecure())
		}
		if len(cfg.Headers) > 0 {
			opts = append(opts, otlploghttp.WithHeaders(cfg.Headers))
		}
		return otlploghttp.New(ctx, opts...)
	default:
		return nil, fmt.Errorf("unsupported OTLP protocol %q", cfg.Protocol)
	}
}

// stripURLScheme returns the host:port portion of an OTLP endpoint URL,
// which the gRPC/HTTP exporters' WithEndpoint expects (they toggle TLS via
// WithInsecure, not the scheme). A scheme-less endpoint (e.g.
// "localhost:4317") is returned unchanged; a path is dropped here and
// re-applied by the caller via WithURLPath. Duplicated from Stirrup rather
// than shared — the two services are separate modules.
func stripURLScheme(endpoint string) string {
	for _, scheme := range []string{"https://", "http://"} {
		if rest, ok := strings.CutPrefix(endpoint, scheme); ok {
			host, _, _ := strings.Cut(rest, "/")
			return host
		}
	}
	host, _, _ := strings.Cut(endpoint, "/")
	return host
}

// urlPath returns the path component of an OTLP endpoint URL, or "" when
// the endpoint carries no path beyond the host. Only meaningful for the
// http/protobuf transport, where a managed gateway (e.g. Grafana Cloud)
// serves OTLP under a base path like "/otlp".
func urlPath(endpoint string) string {
	trimmed := endpoint
	for _, scheme := range []string{"https://", "http://"} {
		if rest, ok := strings.CutPrefix(endpoint, scheme); ok {
			trimmed = rest
			break
		}
	}
	if i := strings.IndexByte(trimmed, '/'); i >= 0 {
		return trimmed[i:]
	}
	return ""
}

// joinSignalPath appends the per-signal "/v1/<signal>" suffix to a base
// gateway path, matching what the OTLP/HTTP SDK does when given an endpoint
// without an explicit URL path: a managed gateway expects the configured
// URL to end in its base prefix (e.g. "/otlp") and resolves the per-signal
// segment itself, so the operator-supplied prefix is preserved and the
// suffix the SDK would otherwise apply is tacked on here.
func joinSignalPath(basePath, signal string) string {
	return strings.TrimRight(basePath, "/") + "/v1/" + signal
}

// ParseOTLPHeaders parses an OTEL_EXPORTER_OTLP_HEADERS-style value — a
// comma-separated list of "key=value" pairs, e.g.
// "authorization=Bearer abc,x-tenant=acme" — into the header map the OTLP
// exporters accept. Whitespace around each key and value is trimmed. Empty
// pairs (a stray trailing comma) and pairs with an empty key are skipped;
// a value may itself contain '=' (a bearer token, a base64 blob), so only
// the first '=' splits the pair. Returns nil for an empty input, which the
// exporter builders treat as "no headers".
//
// serve.go calls this on the value it reads from the operator's
// TelemetryConfig.HeadersEnv variable, so a bearer token reaches an
// exporter only ever from the environment, never from the YAML file.
func ParseOTLPHeaders(raw string) map[string]string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	headers := make(map[string]string)
	for pair := range strings.SplitSeq(raw, ",") {
		key, value, found := strings.Cut(pair, "=")
		if !found {
			continue
		}
		key = strings.TrimSpace(key)
		if key == "" {
			continue
		}
		headers[key] = strings.TrimSpace(value)
	}
	if len(headers) == 0 {
		return nil
	}
	return headers
}

// isInsecureEndpoint reports whether the endpoint should be dialled without
// TLS: a plain "http://" URL, or any scheme-less endpoint (the typical
// local-collector case, "localhost:4317"). An "https://" endpoint always
// keeps TLS on, so a managed-gateway URL never silently falls back to an
// unencrypted export.
func isInsecureEndpoint(endpoint string) bool {
	if strings.HasPrefix(endpoint, "https://") {
		return false
	}
	if strings.HasPrefix(endpoint, "http://") {
		return true
	}
	return true
}
