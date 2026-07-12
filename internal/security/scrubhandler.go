package security

import (
	"context"
	"log/slog"
)

// ScrubHandler wraps an slog.Handler and redacts known secret patterns
// (see Scrub) from every string attribute value — and the log message
// itself — before delegating to the wrapped handler. It is the seam
// that guarantees a token or credential accidentally handed to a log
// call anywhere in haybale is still redacted before it reaches any sink,
// rather than relying solely on every call site getting that right.
// Every haybale logger should be wrapped in a ScrubHandler (see
// cmd/haybale/cmd/serve.go), exactly as Stirrup wraps its own harness
// logger in harness/internal/observability.ScrubHandler — this is that
// same pattern, trimmed to haybale's single-sink, no-OTel logging needs.
//
// ScrubHandler never logs a full URL either: Scrub's url_userinfo
// pattern redacts credentials embedded in a URL's userinfo component,
// but the URL's path/query themselves are untouched by design — no
// haybale call site should ever pass a full request URL as a log
// attribute in the first place (see internal/proxy, which logs
// host/owner/repo/verb as separate structured fields instead), so this
// handler is a backstop, not the primary mechanism.
type ScrubHandler struct {
	inner slog.Handler
}

// NewScrubHandler wraps inner in a ScrubHandler.
func NewScrubHandler(inner slog.Handler) *ScrubHandler {
	return &ScrubHandler{inner: inner}
}

// Enabled delegates to the inner handler.
func (h *ScrubHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.inner.Enabled(ctx, level)
}

// Handle scrubs the record's message and every attribute value, then
// delegates to the inner handler. The original record is not modified.
func (h *ScrubHandler) Handle(ctx context.Context, r slog.Record) error {
	scrubbed := slog.NewRecord(r.Time, r.Level, Scrub(r.Message), r.PC)
	r.Attrs(func(a slog.Attr) bool {
		scrubbed.AddAttrs(scrubAttr(a))
		return true
	})
	return h.inner.Handle(ctx, scrubbed)
}

// WithAttrs scrubs attrs' string values, then delegates to the inner
// handler.
func (h *ScrubHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	scrubbed := make([]slog.Attr, len(attrs))
	for i, a := range attrs {
		scrubbed[i] = scrubAttr(a)
	}
	return &ScrubHandler{inner: h.inner.WithAttrs(scrubbed)}
}

// WithGroup delegates to the inner handler.
func (h *ScrubHandler) WithGroup(name string) slog.Handler {
	return &ScrubHandler{inner: h.inner.WithGroup(name)}
}

// scrubAttr scrubs a's value when it's a string, recursing into group
// attrs; every other Kind (int, bool, time, ...) is returned unchanged,
// since Scrub only ever operates on strings.
func scrubAttr(a slog.Attr) slog.Attr {
	switch a.Value.Kind() {
	case slog.KindString:
		return slog.Attr{Key: a.Key, Value: slog.StringValue(Scrub(a.Value.String()))}
	case slog.KindGroup:
		group := a.Value.Group()
		scrubbed := make([]slog.Attr, len(group))
		for i, ga := range group {
			scrubbed[i] = scrubAttr(ga)
		}
		return slog.Attr{Key: a.Key, Value: slog.GroupValue(scrubbed...)}
	default:
		return a
	}
}
