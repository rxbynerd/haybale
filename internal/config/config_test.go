package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidate(t *testing.T) {
	validUpstream := Upstream{Host: "github.com", BaseURL: "https://github.com"}

	tests := []struct {
		name    string
		cfg     Config
		wantErr string // substring expected in the error; "" means no error
	}{
		{
			name: "valid minimal config",
			cfg: Config{
				Listen:    ":8466",
				LogLevel:  "info",
				Upstreams: []Upstream{validUpstream},
			},
		},
		{
			name: "log level is case-insensitive",
			cfg: Config{
				Listen:    ":8466",
				LogLevel:  "DEBUG",
				Upstreams: []Upstream{validUpstream},
			},
		},
		{
			name: "unknown log level",
			cfg: Config{
				Listen:    ":8466",
				LogLevel:  "verbose",
				Upstreams: []Upstream{validUpstream},
			},
			wantErr: "logLevel",
		},
		{
			name: "no upstreams",
			cfg: Config{
				Listen:   ":8466",
				LogLevel: "info",
			},
			wantErr: "at least one upstream",
		},
		{
			name: "upstream missing host",
			cfg: Config{
				Listen:    ":8466",
				LogLevel:  "info",
				Upstreams: []Upstream{{BaseURL: "https://github.com"}},
			},
			wantErr: "host is required",
		},
		{
			name: "upstream missing baseURL",
			cfg: Config{
				Listen:    ":8466",
				LogLevel:  "info",
				Upstreams: []Upstream{{Host: "github.com"}},
			},
			wantErr: "baseURL is required",
		},
		{
			name: "upstream baseURL missing scheme",
			cfg: Config{
				Listen:    ":8466",
				LogLevel:  "info",
				Upstreams: []Upstream{{Host: "github.com", BaseURL: "github.com"}},
			},
			wantErr: "must be an absolute URL",
		},
		{
			name: "duplicate upstream host",
			cfg: Config{
				Listen:   ":8466",
				LogLevel: "info",
				Upstreams: []Upstream{
					{Host: "github.com", BaseURL: "https://github.com"},
					{Host: "github.com", BaseURL: "https://github.example.com"},
				},
			},
			wantErr: "duplicate host",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cfg.Validate()
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("Validate() unexpected error: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("Validate() = nil error, want error containing %q", tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("Validate() error = %q, want substring %q", err.Error(), tt.wantErr)
			}
		})
	}
}

func TestApplyDefaults(t *testing.T) {
	cfg := Config{
		Upstreams: []Upstream{{Host: "github.com", BaseURL: "https://github.com"}},
	}
	cfg.applyDefaults()

	if cfg.Listen != defaultListen {
		t.Errorf("Listen = %q, want default %q", cfg.Listen, defaultListen)
	}
	if cfg.LogLevel != defaultLogLevel {
		t.Errorf("LogLevel = %q, want default %q", cfg.LogLevel, defaultLogLevel)
	}
}

func TestApplyDefaultsDoesNotOverrideExplicitValues(t *testing.T) {
	cfg := Config{
		Listen:   "127.0.0.1:9000",
		LogLevel: "debug",
	}
	cfg.applyDefaults()

	if cfg.Listen != "127.0.0.1:9000" {
		t.Errorf("Listen = %q, want unchanged %q", cfg.Listen, "127.0.0.1:9000")
	}
	if cfg.LogLevel != "debug" {
		t.Errorf("LogLevel = %q, want unchanged %q", cfg.LogLevel, "debug")
	}
}

func TestLoad(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "haybale.yaml")
	yamlContent := `
listen: ":9999"
logLevel: warn
upstreams:
  - host: github.com
    baseURL: https://github.com
  - host: git.internal.example
    baseURL: https://git.internal.example
`
	if err := os.WriteFile(path, []byte(yamlContent), 0o600); err != nil {
		t.Fatalf("os.WriteFile: %v", err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() unexpected error: %v", err)
	}
	if cfg.Listen != ":9999" {
		t.Errorf("Listen = %q, want %q", cfg.Listen, ":9999")
	}
	if cfg.LogLevel != "warn" {
		t.Errorf("LogLevel = %q, want %q", cfg.LogLevel, "warn")
	}
	if len(cfg.Upstreams) != 2 {
		t.Fatalf("len(Upstreams) = %d, want 2", len(cfg.Upstreams))
	}
	if cfg.Upstreams[0].Host != "github.com" || cfg.Upstreams[0].BaseURL != "https://github.com" {
		t.Errorf("Upstreams[0] = %+v, want {github.com https://github.com}", cfg.Upstreams[0])
	}
}

func TestLoadAppliesDefaults(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "haybale.yaml")
	yamlContent := `
upstreams:
  - host: github.com
    baseURL: https://github.com
`
	if err := os.WriteFile(path, []byte(yamlContent), 0o600); err != nil {
		t.Fatalf("os.WriteFile: %v", err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() unexpected error: %v", err)
	}
	if cfg.Listen != defaultListen {
		t.Errorf("Listen = %q, want default %q", cfg.Listen, defaultListen)
	}
	if cfg.LogLevel != defaultLogLevel {
		t.Errorf("LogLevel = %q, want default %q", cfg.LogLevel, defaultLogLevel)
	}
}

func TestLoadRejectsInvalidConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "haybale.yaml")
	// No upstreams: Validate() must fail, and Load() must surface it.
	if err := os.WriteFile(path, []byte("listen: \":8466\"\n"), 0o600); err != nil {
		t.Fatalf("os.WriteFile: %v", err)
	}

	_, err := Load(path)
	if err == nil {
		t.Fatal("Load() = nil error, want error for a config with no upstreams")
	}
	if !strings.Contains(err.Error(), "at least one upstream") {
		t.Fatalf("Load() error = %q, want substring %q", err.Error(), "at least one upstream")
	}
}

func TestLoadMissingFile(t *testing.T) {
	_, err := Load(filepath.Join(t.TempDir(), "does-not-exist.yaml"))
	if err == nil {
		t.Fatal("Load() = nil error, want error for a missing file")
	}
}

func TestLoadMalformedYAML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "haybale.yaml")
	if err := os.WriteFile(path, []byte("listen: [this is not valid yaml for a string field\n"), 0o600); err != nil {
		t.Fatalf("os.WriteFile: %v", err)
	}

	_, err := Load(path)
	if err == nil {
		t.Fatal("Load() = nil error, want error for malformed YAML")
	}
}
