package security

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"
)

func TestScrubHandlerRedactsAttrValues(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(NewScrubHandler(slog.NewJSONHandler(&buf, nil)))

	logger.Warn("credential leaked", "authorization", "Bearer haybale-secret-token-value", "repo", "github.com/acme/widgets")

	line := buf.String()
	if strings.Contains(line, "haybale-secret-token-value") {
		t.Errorf("log line = %q, must not contain the raw token", line)
	}
	if !strings.Contains(line, "[REDACTED]") {
		t.Errorf("log line = %q, want the redaction placeholder", line)
	}
	// Non-secret attributes must survive untouched.
	if !strings.Contains(line, `"repo":"github.com/acme/widgets"`) {
		t.Errorf("log line = %q, want unrelated attrs preserved", line)
	}
}

func TestScrubHandlerRedactsMessage(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(NewScrubHandler(slog.NewJSONHandler(&buf, nil)))

	logger.Warn("token ghp_1234567890abcdefghijklmnopqrstuvwx found in body")

	line := buf.String()
	if strings.Contains(line, "ghp_1234567890abcdefghijklmnopqrstuvwx") {
		t.Errorf("log line = %q, must not contain the raw token", line)
	}
}

func TestScrubHandlerRedactsWithAttrs(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(NewScrubHandler(slog.NewJSONHandler(&buf, nil))).With("authorization", "Basic aGF5YmFsZS1zZWNyZXQ=")

	logger.Info("request handled")

	line := buf.String()
	if strings.Contains(line, "aGF5YmFsZS1zZWNyZXQ=") {
		t.Errorf("log line = %q, must not contain the raw Basic-auth value from With()", line)
	}
}

func TestScrubHandlerRedactsGroupedAttrs(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(NewScrubHandler(slog.NewJSONHandler(&buf, nil)))

	logger.Warn("grouped", slog.Group("request",
		slog.String("authorization", "Bearer haybale-secret-token-value"),
		slog.String("repo", "github.com/acme/widgets"),
	))

	line := buf.String()
	if strings.Contains(line, "haybale-secret-token-value") {
		t.Errorf("log line = %q, must not contain the raw token nested in a group", line)
	}
	if !strings.Contains(line, `"repo":"github.com/acme/widgets"`) {
		t.Errorf("log line = %q, want the non-secret grouped attr preserved", line)
	}
}

func TestScrubHandlerLeavesNonStringAttrsUnchanged(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(NewScrubHandler(slog.NewJSONHandler(&buf, nil)))

	logger.Info("proxied request", "status", 200, "bytesIn", int64(4096))

	line := buf.String()
	if !strings.Contains(line, `"status":200`) {
		t.Errorf("log line = %q, want numeric status preserved", line)
	}
	if !strings.Contains(line, `"bytesIn":4096`) {
		t.Errorf("log line = %q, want numeric bytesIn preserved", line)
	}
}

func TestScrubHandlerEnabledDelegates(t *testing.T) {
	inner := slog.NewJSONHandler(&bytes.Buffer{}, &slog.HandlerOptions{Level: slog.LevelWarn})
	h := NewScrubHandler(inner)
	logger := slog.New(h)

	ctx := context.Background()
	if logger.Handler().Enabled(ctx, slog.LevelInfo) {
		t.Error("Enabled(Info) = true, want false when the inner handler is configured for Warn")
	}
	if !logger.Handler().Enabled(ctx, slog.LevelWarn) {
		t.Error("Enabled(Warn) = false, want true when the inner handler is configured for Warn")
	}
}
