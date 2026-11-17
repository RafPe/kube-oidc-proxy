// Copyright Jetstack Ltd. See LICENSE for details.

// Package ctxerr classifies the context errors a dependency call fails with.
// A cancellation or an expired deadline does not say whose context ended: the
// inbound request's, because the client went away, or one the proxy derived
// for the call, because the dependency did not answer within the proxy's
// budget. The first is a per-request condition, the second a dependency
// failure, and every caller that reports such a failure tells them apart here.
//
// It depends on nothing in this module, so both the proxy and the reviewers it
// calls can import it.
package ctxerr

import (
	"context"
	"errors"
)

// Is reports whether err is, or wraps, a cancellation or an expired deadline.
func Is(err error) bool {
	return errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
}

// ClientGone reports whether err is a context error caused by the inbound
// request's own context ending -- the client hung up, or its deadline passed --
// rather than by a dependency running out of the proxy's budget. requestCtx is
// the inbound request's context, not a context derived for the dependency
// call.
func ClientGone(requestCtx context.Context, err error) bool {
	return requestCtx.Err() != nil && Is(err)
}
