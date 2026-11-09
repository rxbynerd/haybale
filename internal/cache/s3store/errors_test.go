package s3store

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	smithyhttp "github.com/aws/smithy-go/transport/http"
)

// statusError is a provider failure that carries an HTTP status, as an STS
// or instance-metadata response error does.
type statusError struct{ status int }

func (e statusError) Error() string { return "provider answered with an error" }

func (e statusError) HTTPStatusCode() int { return e.status }

// timeoutError is a network error that timed out.
type timeoutError struct{}

func (timeoutError) Error() string   { return "i/o timeout" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }

func TestCredentialChainFailuresAreTransientOrMissing(t *testing.T) {
	tests := []struct {
		name  string
		cause error
		want  string
	}{
		{"STS answers 503", statusError{http.StatusServiceUnavailable}, codeCredsDown},
		{"STS throttles", statusError{http.StatusTooManyRequests}, codeCredsDown},
		{"the provider cannot be reached", &smithyhttp.RequestSendError{Err: errors.New("dial tcp: connection refused")}, codeCredsDown},
		{"the provider times out", timeoutError{}, codeCredsDown},
		{"instance metadata answers 404", statusError{http.StatusNotFound}, codeNoCredentials},
		{"web identity is refused", statusError{http.StatusForbidden}, codeNoCredentials},
		{"no provider in the chain", errors.New("failed to refresh cached credentials, no EC2 IMDS role found"), codeNoCredentials},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := wrapError(context.Background(), "get", testKey, &credentialsError{err: tt.cause})
			var e *Error
			if !errors.As(err, &e) || e.Code != tt.want || e.Status != 0 {
				t.Errorf("wrapError = %v, want %s with no status", err, tt.want)
			}
		})
	}
}

func TestInstanceMetadataAnswering404IsNoCredentials(t *testing.T) {
	isolateAWSEnv(t)
	for _, name := range []string{"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"} {
		if err := os.Unsetenv(name); err != nil {
			t.Fatal(err)
		}
	}
	imds := httptest.NewServer(http.NotFoundHandler())
	t.Cleanup(imds.Close)
	t.Setenv("AWS_EC2_METADATA_DISABLED", "false")
	t.Setenv("AWS_EC2_METADATA_SERVICE_ENDPOINT", imds.URL)
	s := newStore(t, testConfig("http://127.0.0.1:1"))

	_, _, err := s.Get(context.Background(), testKey, 0)
	var e *Error
	if !errors.As(err, &e) || e.Code != codeNoCredentials {
		t.Fatalf("Get with instance metadata answering 404: err = %v, want %s", err, codeNoCredentials)
	}
}
