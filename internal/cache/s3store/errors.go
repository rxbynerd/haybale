package s3store

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"

	"github.com/aws/smithy-go"
	smithyhttp "github.com/aws/smithy-go/transport/http"

	"github.com/rxbynerd/haybale/internal/cache"
)

// ErrTooLarge is returned by Put for an object larger than the 5 GiB
// limit of a single PutObject request. No request is sent. It is
// cache.ErrTooLarge, so the cache can recognise it without importing this
// package.
var ErrTooLarge = cache.ErrTooLarge

// errHeaderTimeout is the cancellation cause of a request whose response
// did not arrive within Config.HeaderTimeout.
var errHeaderTimeout = errors.New("s3store: header timeout")

// Error codes for failures that carry no service error code.
const (
	codeHeaderTimeout = "HeaderTimeout"
	codeCanceled      = "Canceled"
	codeDeadline      = "DeadlineExceeded"
	codeSendFailed    = "RequestSendFailed"
	codeRequestFailed = "RequestFailed"
	codeBadResponse   = "InvalidResponse"
	codeNoCredentials = "NoCredentials"
	codeTLSFailed     = "TLSVerificationFailed"
)

// Error is the error a Store operation returns when a request fails. It
// holds only the operation, the object key (a hashed path) or list
// prefix, the service error code and the HTTP status: never the SDK's
// error text, request ids or credential material.
//
// errors.Is reports cache.ErrNotFound for a missing object,
// context.DeadlineExceeded for a header timeout or caller deadline, and
// context.Canceled for a cancelled caller context.
type Error struct {
	// Op is the operation: "stat", "get", "put", "delete" or "list".
	Op string
	// Key is the object key, or the prefix for "list", without the
	// store prefix.
	Key string
	// Code is the S3 error code, such as "NoSuchKey" or "AccessDenied",
	// or one of "HeaderTimeout", "Canceled", "DeadlineExceeded",
	// "NoCredentials", "TLSVerificationFailed", "RequestSendFailed",
	// "RequestFailed" or "InvalidResponse" when the service sent no code.
	// NoCredentials means the SDK's credential chain produced none; a
	// TLSVerificationFailed request never reached the service because its
	// certificate did not verify.
	Code string
	// Status is the HTTP status of the response, or 0 when none arrived.
	Status int

	sentinel error
}

// Error formats e as "s3store: <op> <key>: <code> (HTTP <status>)",
// omitting the status when no response arrived.
func (e *Error) Error() string {
	if e.Status == 0 {
		return fmt.Sprintf("s3store: %s %s: %s", e.Op, e.Key, e.Code)
	}
	return fmt.Sprintf("s3store: %s %s: %s (HTTP %d)", e.Op, e.Key, e.Code, e.Status)
}

// Unwrap returns the sentinel e matches, or nil.
func (e *Error) Unwrap() error { return e.sentinel }

// wrapError converts an SDK error from op on key into an *Error. ctx is
// the request context, whose cancellation cause distinguishes a header
// timeout from the caller's own cancellation.
func wrapError(ctx context.Context, op, key string, err error) error {
	e := &Error{Op: op, Key: key}
	var statusErr interface{ HTTPStatusCode() int }
	if errors.As(err, &statusErr) {
		e.Status = statusErr.HTTPStatusCode()
	}
	var apiErr smithy.APIError
	var sendErr *smithyhttp.RequestSendError
	switch {
	case errors.Is(context.Cause(ctx), errHeaderTimeout):
		e.Code, e.sentinel = codeHeaderTimeout, context.DeadlineExceeded
	case errors.Is(ctx.Err(), context.DeadlineExceeded) || errors.Is(err, context.DeadlineExceeded):
		e.Code, e.sentinel = codeDeadline, context.DeadlineExceeded
	case errors.Is(ctx.Err(), context.Canceled) || errors.Is(err, context.Canceled):
		e.Code, e.sentinel = codeCanceled, context.Canceled
	case isCredentialsError(err):
		e.Code, e.Status = codeNoCredentials, 0
	case isTLSVerificationError(err):
		e.Code, e.Status = codeTLSFailed, 0
	case errors.As(err, &apiErr) && apiErr.ErrorCode() != "":
		e.Code = apiErr.ErrorCode()
	case errors.As(err, &sendErr):
		e.Code = codeSendFailed
	default:
		e.Code = codeRequestFailed
	}
	if isNotFound(e) {
		e.sentinel = cache.ErrNotFound
	}
	return e
}

// isCredentialsError reports whether err is a failure to obtain
// credentials, which credentialsProvider marks.
func isCredentialsError(err error) bool {
	var ce *credentialsError
	return errors.As(err, &ce)
}

// isTLSVerificationError reports whether err is a server certificate that
// failed verification.
func isTLSVerificationError(err error) bool {
	var (
		verifyErr    *tls.CertificateVerificationError
		authorityErr x509.UnknownAuthorityError
		hostnameErr  x509.HostnameError
		invalidErr   x509.CertificateInvalidError
	)
	return errors.As(err, &verifyErr) || errors.As(err, &authorityErr) ||
		errors.As(err, &hostnameErr) || errors.As(err, &invalidErr)
}

// credentialsError marks an error from the SDK's credential chain, which
// the SDK otherwise reports as untyped text.
type credentialsError struct{ err error }

func (e *credentialsError) Error() string { return e.err.Error() }

func (e *credentialsError) Unwrap() error { return e.err }

// isNotFound reports whether e is the service saying the object does not
// exist. A 404 for a missing bucket is not.
func isNotFound(e *Error) bool {
	switch e.Code {
	case "NoSuchKey":
		return true
	case "NotFound":
		return e.Status == 404
	default:
		return false
	}
}

// responseError reports a response the store cannot use.
func responseError(op, key string, status int) error {
	return &Error{Op: op, Key: key, Code: codeBadResponse, Status: status}
}
