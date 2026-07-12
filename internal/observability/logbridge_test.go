package observability

import (
	"context"
	"errors"
	"log/slog"
	"testing"
	"time"

	"go.opentelemetry.io/otel/trace"
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
