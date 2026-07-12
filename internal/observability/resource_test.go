package observability

import (
	"testing"

	"go.opentelemetry.io/otel/attribute"
)

// resourceAttrs flattens a built Resource into a key->string map for
// assertions. Non-string attribute values are rendered via Emit().
func resourceAttrs(t *testing.T, opts ResourceOptions) map[string]string {
	t.Helper()
	res := BuildResource(opts)
	out := make(map[string]string)
	for _, kv := range res.Attributes() {
		out[string(kv.Key)] = kv.Value.String()
	}
	return out
}

func TestBuildResourceIdentity(t *testing.T) {
	// Not parallel: exercises process env vars via t.Setenv.
	t.Setenv(envEnvironment, "")
	t.Setenv(envServiceNamespace, "")

	attrs := resourceAttrs(t, ResourceOptions{Version: "1.2.3"})

	if got := attrs[string(attribute.Key("service.name"))]; got != ServiceName {
		t.Errorf("service.name = %q, want %q", got, ServiceName)
	}
	if got := attrs["service.version"]; got != "1.2.3" {
		t.Errorf("service.version = %q, want %q", got, "1.2.3")
	}
	if got := attrs["service.namespace"]; got != DefaultServiceNamespace {
		t.Errorf("service.namespace = %q, want default %q", got, DefaultServiceNamespace)
	}
	if got := attrs["deployment.environment"]; got != DefaultEnvironment {
		t.Errorf("deployment.environment = %q, want default %q", got, DefaultEnvironment)
	}
	if attrs["service.instance.id"] == "" {
		t.Error("service.instance.id is empty, want a generated id")
	}
	// The legacy key is required; the newer .name suffix must not be used
	// (see BuildResource's doc comment — it would break existing dashboards).
	if _, ok := attrs["deployment.environment.name"]; ok {
		t.Error("deployment.environment.name is set; must use the legacy deployment.environment key")
	}
}

func TestBuildResourceExplicitOverEnvOverDefault(t *testing.T) {
	t.Setenv(envEnvironment, "from-env")
	t.Setenv(envServiceNamespace, "ns-from-env")

	// Explicit opts win over env.
	attrs := resourceAttrs(t, ResourceOptions{Environment: "prod", ServiceNamespace: "team-a"})
	if got := attrs["deployment.environment"]; got != "prod" {
		t.Errorf("deployment.environment = %q, want explicit %q", got, "prod")
	}
	if got := attrs["service.namespace"]; got != "team-a" {
		t.Errorf("service.namespace = %q, want explicit %q", got, "team-a")
	}

	// Empty opts fall through to env.
	attrs = resourceAttrs(t, ResourceOptions{})
	if got := attrs["deployment.environment"]; got != "from-env" {
		t.Errorf("deployment.environment = %q, want env %q", got, "from-env")
	}
	if got := attrs["service.namespace"]; got != "ns-from-env" {
		t.Errorf("service.namespace = %q, want env %q", got, "ns-from-env")
	}
}

func TestBuildResourceSanitisesHostileEnv(t *testing.T) {
	// A hostile env value (newline, over-length, illegal chars) must not
	// reach the resource verbatim — it falls back to the default.
	t.Setenv(envEnvironment, "bad\nvalue")
	t.Setenv(envServiceNamespace, "")

	attrs := resourceAttrs(t, ResourceOptions{})
	if got := attrs["deployment.environment"]; got != DefaultEnvironment {
		t.Errorf("deployment.environment = %q, want fallback %q for hostile env", got, DefaultEnvironment)
	}
}

func TestBuildResourceEmptyVersionFallsBackToDev(t *testing.T) {
	t.Setenv(envEnvironment, "")
	t.Setenv(envServiceNamespace, "")
	attrs := resourceAttrs(t, ResourceOptions{})
	if got := attrs["service.version"]; got != "dev" {
		t.Errorf("service.version = %q, want %q for empty Version", got, "dev")
	}
}

func TestSanitiseLabel(t *testing.T) {
	t.Parallel()
	tests := []struct {
		in, fallback, want string
	}{
		{"prod", "def", "prod"},
		{"", "def", "def"},
		{"has space", "def", "def"},
		{"with\nnewline", "def", "def"},
		{"ok.dash-under_123", "def", "ok.dash-under_123"},
	}
	for _, tt := range tests {
		if got := sanitiseLabel(tt.in, tt.fallback); got != tt.want {
			t.Errorf("sanitiseLabel(%q, %q) = %q, want %q", tt.in, tt.fallback, got, tt.want)
		}
	}
}

func TestInstanceIDStableAndHex(t *testing.T) {
	t.Parallel()
	a, b := InstanceID(), InstanceID()
	if a != b {
		t.Errorf("InstanceID() not stable: %q != %q", a, b)
	}
	if len(a) != 32 { // 16 bytes hex-encoded
		t.Errorf("InstanceID() length = %d, want 32", len(a))
	}
}
