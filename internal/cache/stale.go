package cache

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/rxbynerd/haybale/internal/gitproto"
	"github.com/rxbynerd/haybale/internal/observability"
	"github.com/rxbynerd/haybale/internal/security"
	"github.com/rxbynerd/haybale/internal/upstream"
)

// UpstreamStatusHeader is set by a Fetcher on a response it rewrote, to
// the status upstream actually sent: an upstream 401 or 403 arrives as a
// 502 carrying "Haybale-Upstream-Status: 401". A Fetcher removes any copy
// upstream sent. The cache honours the header only in that form and never
// relays it.
const UpstreamStatusHeader = "Haybale-Upstream-Status"

// Reasons a request was eligible for stale service, recorded on the
// cache_stale_served event.
const (
	staleReasonConnect               = "connect"
	staleReasonCredentialUnavailable = "credential_unavailable" //nolint:gosec // G101: an event reason, not a credential
	staleReasonHeaderTimeout         = "header_timeout"
	staleReasonUpstreamStatus        = "upstream_status"
	staleReasonHealthGate            = "health_gate"
)

// tlsHandshakeTimeoutText is the text of net/http's TLS handshake
// timeout error, whose type is unexported.
const tlsHandshakeTimeoutText = "net/http: TLS handshake timeout"

// upstreamResult classifies the outcome of a fill's upstream request for
// stale service and the health gate.
type upstreamResult struct {
	// eligible reports that the request may be answered from a stale
	// entry.
	eligible bool
	// reason labels why it is eligible.
	reason string
	// status is the upstream response status; zero when none arrived.
	status int
	// signal is what the result tells the host's health gate.
	signal gateSignal
}

// classifyFetchError classifies a Fetcher error. headerTimedOut reports
// that the fill's response-header timeout cancelled the request. A
// credential source that could not reach its API, and a connection that
// failed before any request was sent, are outages: eligible, and they
// open the health gate. A header timeout is eligible but leaves the gate
// alone, since a slow repository is not an unreachable host. Every other
// error is neither.
func classifyFetchError(err error, headerTimedOut bool) upstreamResult {
	switch {
	case headerTimedOut:
		return upstreamResult{eligible: true, reason: staleReasonHeaderTimeout}
	case errors.Is(err, upstream.ErrUnavailable):
		return upstreamResult{eligible: true, reason: staleReasonCredentialUnavailable, signal: gateFailure}
	case connectFailure(err):
		return upstreamResult{eligible: true, reason: staleReasonConnect, signal: gateFailure}
	default:
		return upstreamResult{}
	}
}

// classifyStatus classifies an upstream response status. 500, 502, 503
// and 504 are eligible; the gate neither opens nor closes on them. Any
// other status shows the host is reachable and closes the gate; 401 and
// 403 (a rejected credential), 429 and the other 4xx are policy signals,
// never outages.
func classifyStatus(status int) upstreamResult {
	switch status {
	case http.StatusInternalServerError, http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		return upstreamResult{eligible: true, reason: staleReasonUpstreamStatus, status: status}
	default:
		return upstreamResult{status: status, signal: gateSuccess}
	}
}

// connectFailure reports whether err shows the upstream connection
// failed before a request could be sent: name resolution, the dial, or
// the TLS handshake. Errors that may arise after a connection exists,
// such as a reset or an EOF, are not counted.
func connectFailure(err error) bool {
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		switch opErr.Op {
		case "dial", "remote error", "local error":
			return true
		}
	}
	var (
		dnsErr       *net.DNSError
		verifyErr    *tls.CertificateVerificationError
		recordErr    tls.RecordHeaderError
		alertErr     tls.AlertError
		authorityErr x509.UnknownAuthorityError
		hostnameErr  x509.HostnameError
		invalidErr   x509.CertificateInvalidError
	)
	switch {
	case errors.As(err, &dnsErr), errors.As(err, &verifyErr), errors.As(err, &recordErr),
		errors.As(err, &alertErr), errors.As(err, &authorityErr), errors.As(err, &hostnameErr),
		errors.As(err, &invalidErr):
		return true
	}
	var timeout interface {
		error
		Timeout() bool
	}
	return errors.As(err, &timeout) && timeout.Timeout() && timeout.Error() == tlsHandshakeTimeoutText
}

// upstreamStatus returns the status upstream sent for resp and removes
// UpstreamStatusHeader so it is never relayed. The header is honoured
// only on a 502 and only for 401 or 403, the Fetcher's credential
// rewrite; in any other combination the response status stands.
func upstreamStatus(resp *http.Response) int {
	raw := resp.Header.Get(UpstreamStatusHeader)
	resp.Header.Del(UpstreamStatusHeader)
	if resp.StatusCode != http.StatusBadGateway {
		return resp.StatusCode
	}
	switch raw {
	case strconv.Itoa(http.StatusUnauthorized):
		return http.StatusUnauthorized
	case strconv.Itoa(http.StatusForbidden):
		return http.StatusForbidden
	default:
		return resp.StatusCode
	}
}

// staleService describes a fill answered from a stale entry.
type staleService struct {
	reason    string
	fwdStatus int
	// createdAt is the authenticated creation time of the entry served.
	createdAt time.Time
	// fallback is what subscribers receive when a remote copy cannot be
	// spooled after all.
	fallback fillOutcome
}

// staleEnabled reports whether stale-if-error is configured.
func (c *Cache) staleEnabled() bool { return c.opts.StaleIfErrorFor > 0 }

// openStaleEntry opens the tier-1 entry for key when it may be served
// stale: it verifies, is not covered by a purge, and is no older than
// StaleIfErrorFor. The accessRecheck and refsMaxAge rules do not apply.
// An entry that fails verification, is covered by a purge or is past
// retention is deleted. The caller closes the result.
func (c *Cache) openStaleEntry(key entryKey, repo gitproto.Repo, class string) *openedEntry {
	e := c.openEntry(key, repo, class, false)
	if e == nil {
		return nil
	}
	age := c.now().Sub(e.sr.Header().CreatedAt)
	switch {
	case age > c.opts.Retention:
		_ = c.store.DeleteEntry(e.entry)
		e.close()
		return nil
	case age > c.opts.StaleIfErrorFor:
		e.close()
		return nil
	}
	return e
}

// staleAcceptable applies the stale rules to a remote entry's header,
// and refuses a refs entry created before this process's last push to
// the repository. An entry past retention or older than the repository's
// last purge is deleted from the remote tier in the background.
func (f *fill) staleAcceptable(h entryHeader) bool {
	c := f.c
	age := c.now().Sub(h.CreatedAt)
	switch {
	case age > c.opts.Retention || c.purges.covers(f.key, h.CreatedAt):
		f.expireRemote()
		return false
	case age > c.opts.StaleIfErrorFor:
		return false
	case f.prePushRefs(h):
		return false
	}
	return true
}

// serveStale settles a fill whose upstream request failed with an
// eligible result from a qualifying entry: the tier-1 entry, or else a
// copy of the remote tier's entry spooled as a remote fill. Nothing is
// served unless the repository's purge state is known current.
// fallback is what subscribers receive when they cannot open the tier-1
// entry after all. fillReason labels the fill metric of a tier-1 answer;
// empty records none, for a fill that never contacted upstream. It
// returns false, having settled nothing, when stale service is disabled
// or no entry qualifies.
func (f *fill) serveStale(res upstreamResult, fallback fillOutcome, fillReason string) bool {
	c := f.c
	if !res.eligible || !c.staleEnabled() || !f.purgeCurrent() {
		return false
	}
	st := &staleService{reason: res.reason, fwdStatus: res.status, fallback: fallback}
	if f.tier1Stale(st) {
		if fillReason != "" {
			f.finish(observability.FillResultDiscarded, fillReason, 0)
		}
		f.publishStale(st, fallback)
		return true
	}
	return c.remote != nil && !f.remoteUnavailable && f.fillFromRemote(st)
}

// tier1Stale reports whether the key's tier-1 entry qualifies for stale
// service, and records its creation time in st.
func (f *fill) tier1Stale(st *staleService) bool {
	e := f.c.openStaleEntry(f.key, f.repo, string(f.req.Class))
	if e == nil {
		return false
	}
	st.createdAt = e.sr.Header().CreatedAt
	e.close()
	return true
}

// publishStale tells the fill's subscribers to serve the tier-1 entry st
// describes, or fallback when they cannot open it after all.
func (f *fill) publishStale(st *staleService, fallback fillOutcome) {
	if h := f.c.hooks.beforeStaleOutcome; h != nil {
		h(f.key)
	}
	f.setOutcome(fillOutcome{kind: fillStale, stale: st, fallback: &fallback})
}

// purgeCurrent reports whether the repository's purge state is known
// current for stale service. A fill that started a check beside its
// upstream request, a refs fill or a probe, waits for it; any other fill
// checks the marker itself, which a recent successful check answers
// without a read.
func (f *fill) purgeCurrent() bool {
	if f.purge != nil {
		return f.purge.wait()
	}
	return f.c.purgeCurrent(f.ctx, f.repo, f.key.RepoHash)
}

// logStaleServed records a stale response to one client, whose serving
// began at servedAt; the entry's age is taken at that instant.
func (c *Cache) logStaleServed(identity string, repo gitproto.Repo, class, tier string, st *staleService, servedAt time.Time) {
	security.Log(c.logger, security.EventCacheStaleServed,
		"identity", identity, "host", repo.Host, "owner", repo.Owner, "repo", repo.Name, "class", class,
		"tier", tier, "reason", st.reason, "entryAgeSeconds", int64(servedAt.Sub(st.createdAt)/time.Second))
}
