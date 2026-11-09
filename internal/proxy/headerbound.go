package proxy

import (
	"context"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/rxbynerd/haybale/internal/gitproto"
)

// errReadHeaderTimeout reports a passthrough read whose upstream response
// headers did not arrive within the read header timeout.
var errReadHeaderTimeout = errors.New("proxy: upstream response headers did not arrive within the read header timeout")

// readHeaderBound is the passthrough transport when reads are bounded: it
// cancels a read whose upstream response headers do not arrive within
// timeout. The bound ends once headers arrive, so it never limits a
// transfer. Requests that are not reads pass straight to next.
type readHeaderBound struct {
	next    http.RoundTripper
	timeout time.Duration
}

func (b readHeaderBound) RoundTrip(req *http.Request) (*http.Response, error) {
	cc, ok := req.Context().Value(credentialContextKey{}).(credentialContext)
	if !ok || cc.verb != gitproto.Read {
		return b.next.RoundTrip(req)
	}
	ctx, cancel := context.WithCancel(req.Context())
	timer := time.AfterFunc(b.timeout, cancel)
	resp, err := b.next.RoundTrip(req.WithContext(ctx))
	if !timer.Stop() {
		// The timer fired, so the request, or the body of a response that
		// arrived at the same instant, has been cancelled.
		if err == nil {
			_ = resp.Body.Close()
		}
		cancel()
		return nil, errReadHeaderTimeout
	}
	if err != nil {
		cancel()
		return nil, err
	}
	resp.Body = cancelOnClose{ReadCloser: resp.Body, cancel: cancel}
	return resp, nil
}

// cancelOnClose releases a bounded read's context once its body is
// closed.
type cancelOnClose struct {
	io.ReadCloser
	cancel context.CancelFunc
}

func (b cancelOnClose) Close() error {
	err := b.ReadCloser.Close()
	b.cancel()
	return err
}
