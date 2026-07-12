package observability

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"go.opentelemetry.io/otel/trace"

	"github.com/rxbynerd/haybale/internal/security"
)

// recordingHandler captures the records and attributes it is handed, and
// can be told to fail, so the fan-out and span-context handlers can be
// asserted without a real sink.
type recordingHandler struct {
	records []slog.Record
	attrs   map[string]string
	failErr error
}

func newRecordingHandler() *recordingHandler {
	return &recordingHandler{attrs: map[string]string{}}
}

func (h *recordingHandler) Enabled(context.Context, slog.Level) bool { return true }

func (h *recordingHandler) Handle(_ context.Context, r slog.Record) error {
	h.records = append(h.records, r)
	r.Attrs(func(a slog.Attr) bool {
		h.attrs[a.Key] = a.Value.String()
		return true
	})
	return h.failErr
}

func (h *recordingHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *recordingHandler) WithGroup(string) slog.Handler      { return h }

func TestFanoutHandlerDeliversToEverySink(t *testing.T) {
	t.Parallel()
	a, b := newRecordingHandler(), newRecordingHandler()
	fan := NewFanoutHandler(a, b)

	rec := slog.NewRecord(time.Now(), slog.LevelInfo, "hello", 0)
	if err := fan.Handle(context.Background(), rec); err != nil {
		t.Fatalf("Handle() error = %v", err)
	}
	if len(a.records) != 1 || len(b.records) != 1 {
		t.Errorf("delivered a=%d b=%d records, want 1 each", len(a.records), len(b.records))
	}
}

func TestFanoutHandlerJoinsErrorsWithoutSuppressingOtherSinks(t *testing.T) {
	t.Parallel()
	failing := newRecordingHandler()
	failing.failErr = errors.New("collector down")
	ok := newRecordingHandler()
	fan := NewFanoutHandler(failing, ok)

	err := fan.Handle(context.Background(), slog.NewRecord(time.Now(), slog.LevelInfo, "x", 0))
	if err == nil {
		t.Error("Handle() error = nil, want the failing sink's error")
	}
	// The healthy sink still received the record despite the other failing.
	if len(ok.records) != 1 {
		t.Errorf("healthy sink got %d records, want 1 (a failing sink must not suppress others)", len(ok.records))
	}
}

func TestSpanContextHandlerAddsIDsWhenSpanPresent(t *testing.T) {
	t.Parallel()
	inner := newRecordingHandler()
	h := NewSpanContextHandler(inner)

	traceID, _ := trace.TraceIDFromHex("0123456789abcdef0123456789abcdef")
	spanID, _ := trace.SpanIDFromHex("0123456789abcdef")
	sc := trace.NewSpanContext(trace.SpanContextConfig{
		TraceID:    traceID,
		SpanID:     spanID,
		TraceFlags: trace.FlagsSampled,
	})
	ctx := trace.ContextWithSpanContext(context.Background(), sc)

	if err := h.Handle(ctx, slog.NewRecord(time.Now(), slog.LevelInfo, "m", 0)); err != nil {
		t.Fatalf("Handle() error = %v", err)
	}
	if got := inner.attrs["trace_id"]; got != traceID.String() {
		t.Errorf("trace_id = %q, want %q", got, traceID.String())
	}
	if got := inner.attrs["span_id"]; got != spanID.String() {
		t.Errorf("span_id = %q, want %q", got, spanID.String())
	}
}

func TestSpanContextHandlerNoIDsWithoutSpan(t *testing.T) {
	t.Parallel()
	inner := newRecordingHandler()
	h := NewSpanContextHandler(inner)

	if err := h.Handle(context.Background(), slog.NewRecord(time.Now(), slog.LevelInfo, "m", 0)); err != nil {
		t.Fatalf("Handle() error = %v", err)
	}
	if _, ok := inner.attrs["trace_id"]; ok {
		t.Error("trace_id added without an active span; want none")
	}
}

// toggleHandler is a slog.Handler whose Enabled result is fixed and that
// records whether WithAttrs/WithGroup were called on it, so the fan-out and
// span-context handlers' delegation of the slog.Handler contract can be
// asserted.
type toggleHandler struct {
	enabled   bool
	withAttrs bool
	withGroup bool
}

func (h *toggleHandler) Enabled(context.Context, slog.Level) bool  { return h.enabled }
func (h *toggleHandler) Handle(context.Context, slog.Record) error { return nil }
func (h *toggleHandler) WithAttrs([]slog.Attr) slog.Handler        { h.withAttrs = true; return h }
func (h *toggleHandler) WithGroup(string) slog.Handler             { h.withGroup = true; return h }

func TestFanoutHandlerEnabledIfAnyInnerEnabled(t *testing.T) {
	t.Parallel()
	on := &toggleHandler{enabled: true}
	off := &toggleHandler{enabled: false}
	if !NewFanoutHandler(off, on).Enabled(context.Background(), slog.LevelInfo) {
		t.Error("Enabled() = false with one enabled inner, want true")
	}
	if NewFanoutHandler(off, &toggleHandler{enabled: false}).Enabled(context.Background(), slog.LevelInfo) {
		t.Error("Enabled() = true with all inners disabled, want false")
	}
}

func TestFanoutHandlerWithAttrsAndGroupDelegateToEveryInner(t *testing.T) {
	t.Parallel()
	a, b := &toggleHandler{enabled: true}, &toggleHandler{enabled: true}

	got := NewFanoutHandler(a, b).WithAttrs([]slog.Attr{slog.String("k", "v")})
	if _, ok := got.(*FanoutHandler); !ok {
		t.Errorf("WithAttrs() returned %T, want *FanoutHandler (wrapper must be preserved)", got)
	}
	if !a.withAttrs || !b.withAttrs {
		t.Error("WithAttrs() did not reach every inner handler")
	}

	got = NewFanoutHandler(a, b).WithGroup("g")
	if _, ok := got.(*FanoutHandler); !ok {
		t.Errorf("WithGroup() returned %T, want *FanoutHandler", got)
	}
	if !a.withGroup || !b.withGroup {
		t.Error("WithGroup() did not reach every inner handler")
	}
}

func TestSpanContextHandlerDelegatesContract(t *testing.T) {
	t.Parallel()
	inner := &toggleHandler{enabled: true}
	h := NewSpanContextHandler(inner)

	if !h.Enabled(context.Background(), slog.LevelInfo) {
		t.Error("Enabled() = false, want it to delegate the inner's true")
	}
	if got := h.WithAttrs([]slog.Attr{slog.String("k", "v")}); func() bool { _, ok := got.(*SpanContextHandler); return !ok }() {
		t.Errorf("WithAttrs() returned %T, want *SpanContextHandler (wrapper preserved)", got)
	}
	if !inner.withAttrs {
		t.Error("WithAttrs() did not delegate to the inner handler")
	}
	if got := h.WithGroup("g"); func() bool { _, ok := got.(*SpanContextHandler); return !ok }() {
		t.Errorf("WithGroup() returned %T, want *SpanContextHandler", got)
	}
	if !inner.withGroup {
		t.Error("WithGroup() did not delegate to the inner handler")
	}
}

// TestComposedLoggerChainScrubsCorrelatesAndFansOut assembles the exact
// three-layer chain serve.go builds — SpanContextHandler(ScrubHandler(
// Fanout{sinkA, sinkB})) — and asserts, end to end, that a single record
// logged inside a span with a secret-shaped attribute reaches BOTH sinks,
// with trace_id/span_id stamped AND the secret redacted. This is the
// security invariant the layer ordering exists to guarantee (no value
// leaves the process unscrubbed, on any sink), which no single-layer unit
// test covers.
func TestComposedLoggerChainScrubsCorrelatesAndFansOut(t *testing.T) {
	t.Parallel()
	var bufA, bufB bytes.Buffer
	sinkA := slog.NewTextHandler(&bufA, nil)
	sinkB := slog.NewTextHandler(&bufB, nil)

	chain := NewSpanContextHandler(security.NewScrubHandler(NewFanoutHandler(sinkA, sinkB)))
	logger := slog.New(chain)

	traceID, _ := trace.TraceIDFromHex("0123456789abcdef0123456789abcdef")
	spanID, _ := trace.SpanIDFromHex("0123456789abcdef")
	ctx := trace.ContextWithSpanContext(context.Background(), trace.NewSpanContext(trace.SpanContextConfig{
		TraceID:    traceID,
		SpanID:     spanID,
		TraceFlags: trace.FlagsSampled,
	}))

	// A GitHub App installation-token-shaped secret: the scrubber must
	// redact it before it reaches either sink.
	logger.InfoContext(ctx, "proxied request", "leaked", "ghs_0123456789abcdefghijklmnopqrstuvwxyz")

	for name, buf := range map[string]*bytes.Buffer{"sinkA": &bufA, "sinkB": &bufB} {
		out := buf.String()
		if out == "" {
			t.Fatalf("%s received no record; the fan-out must reach every sink", name)
		}
		if !strings.Contains(out, traceID.String()) {
			t.Errorf("%s missing trace_id %q; got: %s", name, traceID.String(), out)
		}
		if !strings.Contains(out, "[REDACTED]") {
			t.Errorf("%s did not redact the secret; got: %s", name, out)
		}
		if strings.Contains(out, "ghs_0123456789") {
			t.Errorf("%s leaked the raw secret; got: %s", name, out)
		}
	}
}
