package observability

import (
	"context"
	"errors"
	"log/slog"

	"go.opentelemetry.io/otel/trace"
)

// FanoutHandler dispatches every record to two or more inner handlers. It
// exists so haybale's stderr text sink and the OTLP-bridge sink both sit
// BELOW the shared ScrubHandler / SpanContextHandler layers, letting those
// decorators run exactly once while both sinks still receive the enriched,
// already-scrubbed record. The composition serve.go builds is:
//
//	SpanContextHandler ← security.ScrubHandler ← FanoutHandler{text, otelslog}
//
// so no log value reaches either sink unscrubbed, regardless of which sink
// it is. Mirrors Stirrup's fanoutHandler.
type FanoutHandler struct {
	handlers []slog.Handler
}

// NewFanoutHandler builds a FanoutHandler over the given inner handlers.
func NewFanoutHandler(handlers ...slog.Handler) *FanoutHandler {
	return &FanoutHandler{handlers: handlers}
}

// Enabled reports true when any inner handler is enabled for the level, so
// a record is processed if either sink wants it.
func (h *FanoutHandler) Enabled(ctx context.Context, level slog.Level) bool {
	for _, inner := range h.handlers {
		if inner.Enabled(ctx, level) {
			return true
		}
	}
	return false
}

// Handle delivers the record to every enabled inner handler. Errors are
// joined so a failure on one sink (e.g. the OTLP bridge when the collector
// is down) does not suppress delivery to the others — the stderr write
// still happens. Each handler gets its own clone, since a leaf handler may
// mutate the record it receives.
func (h *FanoutHandler) Handle(ctx context.Context, r slog.Record) error {
	var errs []error
	for _, inner := range h.handlers {
		if !inner.Enabled(ctx, r.Level) {
			continue
		}
		if err := inner.Handle(ctx, r.Clone()); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// WithAttrs returns a FanoutHandler whose inner handlers each carry attrs.
func (h *FanoutHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	next := make([]slog.Handler, len(h.handlers))
	for i, inner := range h.handlers {
		next[i] = inner.WithAttrs(attrs)
	}
	return &FanoutHandler{handlers: next}
}

// WithGroup returns a FanoutHandler whose inner handlers each open the group.
func (h *FanoutHandler) WithGroup(name string) slog.Handler {
	next := make([]slog.Handler, len(h.handlers))
	for i, inner := range h.handlers {
		next[i] = inner.WithGroup(name)
	}
	return &FanoutHandler{handlers: next}
}

// SpanContextHandler injects trace_id / span_id attributes onto any record
// emitted with a context that carries a valid span context (Handle checks
// SpanContext.IsValid, not IsSampled — a record is correlated whenever it
// has a span at all, independent of the sampling decision), so a log line
// on the stderr sink can be joined to its trace in a backend. It is the
// outermost
// handler in the chain (above ScrubHandler) so the IDs it adds still pass
// through scrubbing before reaching a sink — trace/span IDs are not
// secrets, but keeping the scrubber the single choke point is the
// invariant worth preserving. Records emitted via the plain (non-Context)
// slog methods carry no span and pass through untouched.
type SpanContextHandler struct {
	inner slog.Handler
}

// NewSpanContextHandler wraps inner with trace-context injection.
func NewSpanContextHandler(inner slog.Handler) *SpanContextHandler {
	return &SpanContextHandler{inner: inner}
}

// Enabled delegates to the inner handler.
func (h *SpanContextHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.inner.Enabled(ctx, level)
}

// Handle adds trace_id / span_id when ctx carries a valid span context,
// then delegates. The original record is not modified.
func (h *SpanContextHandler) Handle(ctx context.Context, r slog.Record) error {
	sc := trace.SpanContextFromContext(ctx)
	if !sc.IsValid() {
		return h.inner.Handle(ctx, r)
	}
	enriched := r.Clone()
	enriched.AddAttrs(
		slog.String("trace_id", sc.TraceID().String()),
		slog.String("span_id", sc.SpanID().String()),
	)
	return h.inner.Handle(ctx, enriched)
}

// WithAttrs delegates, preserving the wrapper.
func (h *SpanContextHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &SpanContextHandler{inner: h.inner.WithAttrs(attrs)}
}

// WithGroup delegates, preserving the wrapper.
func (h *SpanContextHandler) WithGroup(name string) slog.Handler {
	return &SpanContextHandler{inner: h.inner.WithGroup(name)}
}
