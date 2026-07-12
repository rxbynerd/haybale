package cmd

import (
	"log/slog"
	"testing"

	"github.com/rxbynerd/haybale/internal/config"
)

func TestParseLogLevel(t *testing.T) {
	tests := []struct {
		level string
		want  slog.Level
	}{
		{"debug", slog.LevelDebug},
		{"DEBUG", slog.LevelDebug},
		{"info", slog.LevelInfo},
		{"warn", slog.LevelWarn},
		{"WARN", slog.LevelWarn},
		{"error", slog.LevelError},
		{"", slog.LevelInfo}, // unreachable via a Validate()'d config, defaults safely
	}
	for _, tt := range tests {
		if got := parseLogLevel(tt.level); got != tt.want {
			t.Errorf("parseLogLevel(%q) = %v, want %v", tt.level, got, tt.want)
		}
	}
}

func TestBuildUpstreams(t *testing.T) {
	cfg := &config.Config{
		LogLevel: "info",
		Upstreams: []config.Upstream{
			{Host: "github.com", BaseURL: "https://github.com"},
			{Host: "git.internal.example", BaseURL: "https://git.internal.example:8443"},
		},
	}
	// buildUpstreams reuses the *url.URL Validate() parsed onto each
	// Upstream (R1) rather than re-parsing BaseURL itself, so Validate()
	// must run first here — exactly as runServe already does via
	// config.Load.
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}

	upstreams, err := buildUpstreams(cfg)
	if err != nil {
		t.Fatalf("buildUpstreams: %v", err)
	}
	if len(upstreams) != 2 {
		t.Fatalf("len(upstreams) = %d, want 2", len(upstreams))
	}
	if got := upstreams["github.com"].String(); got != "https://github.com" {
		t.Errorf(`upstreams["github.com"] = %q, want %q`, got, "https://github.com")
	}
	if got := upstreams["git.internal.example"].String(); got != "https://git.internal.example:8443" {
		t.Errorf(`upstreams["git.internal.example"] = %q, want %q`, got, "https://git.internal.example:8443")
	}
}
