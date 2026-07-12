package security

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
)

func TestLog(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, nil))

	Log(logger, EventPolicyDenied, "identity", "run-1", "repo", "github.com/acme/widgets")

	line := buf.String()
	if !strings.Contains(line, `"level":"WARN"`) {
		t.Errorf("log line = %q, want level WARN", line)
	}
	for _, want := range []string{`"event":"policy_denied"`, `"identity":"run-1"`, `"repo":"github.com/acme/widgets"`} {
		if !strings.Contains(line, want) {
			t.Errorf("log line = %q, want it to contain %q", line, want)
		}
	}
}
