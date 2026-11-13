// Copyright Jetstack Ltd. See LICENSE for details.

package tokenreview

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	authv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apiserver/pkg/authentication/authenticator"
	"k8s.io/apiserver/pkg/authentication/user"
	clientauthv1 "k8s.io/client-go/kubernetes/typed/authentication/v1"

	"github.com/rafpe/kube-oidc-proxy/pkg/ctxerr"
	"github.com/rafpe/kube-oidc-proxy/pkg/logging"
	"github.com/rafpe/kube-oidc-proxy/pkg/metrics"
)

// liveReviewer submits a TokenReview to the API server for every call. New
// fronts it with a cachedReviewer unless Config switches the cache off.
type liveReviewer struct {
	// logger is the tokenreview-component logger every record this reviewer
	// emits goes through, so each carries component=tokenreview. The
	// per-request correlation id travels on the call's context instead, never
	// bound onto a logger, and Emit reads it from there.
	logger *slog.Logger

	client    clientauthv1.TokenReviewInterface
	audiences []string
	timeout   time.Duration

	// metrics receives the API-call and cache observations.
	metrics *metrics.Recorder
}

var _ authenticator.Token = (*liveReviewer)(nil)

// AuthenticateToken implements authenticator.Token by submitting a
// TokenReview for the bearer token. It returns ok=false with a nil error when
// the API server answers but does not authenticate the token, and an error
// wrapping ErrCreateTokenReview when the review itself failed; callers must
// treat both as unauthenticated (fail closed).
//
// The reviewer records its own outcome: authn.tokenreview.completed for an
// answer, authn.tokenreview.failed for a review that got none.
func (r *liveReviewer) AuthenticateToken(requestCtx context.Context, token string) (*authenticator.Response, bool, error) {
	ctx, cancel := context.WithTimeout(requestCtx, r.timeout)
	defer cancel()

	start := time.Now()

	resp, err := r.client.Create(ctx, r.buildReview(token), metav1.CreateOptions{})
	// Observed at the one place the API server is called: the outcome is the
	// call's, not the caller's, so a cache hit or a fallback never counts.
	switch {
	case err != nil:
		r.metrics.ReviewRequest(metrics.ReviewTokenReview, metrics.ReviewOutcomeFor(err, false), time.Since(start))
		return nil, false, r.reportFailure(requestCtx, fmt.Errorf("%w: %w", ErrCreateTokenReview, err))
	case len(resp.Status.Error) > 0:
		r.metrics.ReviewRequest(metrics.ReviewTokenReview, metrics.ReviewError, time.Since(start))
		return nil, false, r.reportFailure(requestCtx, fmt.Errorf("%w: status error: %s", ErrCreateTokenReview, resp.Status.Error))
	}
	r.metrics.ReviewRequest(metrics.ReviewTokenReview, metrics.ReviewOutcomeFor(nil, resp.Status.Authenticated), time.Since(start))

	logging.Emit(ctx, r.logger, logging.EventAuthnTokenReviewCompleted,
		slog.Bool("authenticated", resp.Status.Authenticated),
		slog.Int64("duration_ms", time.Since(start).Milliseconds()))

	if !resp.Status.Authenticated {
		return nil, false, nil
	}

	return &authenticator.Response{
		Audiences: authenticator.Audiences(resp.Status.Audiences),
		User:      userInfoFrom(resp.Status.User),
	}, true, nil
}

// reportFailure emits authn.tokenreview.failed for err and returns it. requestCtx is
// the caller's context, not the one bounded by the review timeout: a review
// that failed because the client itself went away is a per-request condition
// at DEBUG, so a client cannot drive the ERROR stream by hanging up
// mid-request, while the reviewer's own timeout expiring is a dependency
// failure and stays an ERROR.
func (r *liveReviewer) reportFailure(requestCtx context.Context, err error) error {
	reason, level := metrics.ReasonAuthenticationDependencyError, slog.LevelError
	if ctxerr.ClientGone(requestCtx, err) {
		reason, level = metrics.ReasonClientCanceled, slog.LevelDebug
	}
	logging.EmitLevel(requestCtx, r.logger, logging.EventAuthnTokenReviewFailed, level,
		slog.String("reason", string(reason)), logging.ErrAttr(err))
	return err
}

// userInfoFrom converts the TokenReview status identity into the
// authenticator's user.Info shape.
func userInfoFrom(ui authv1.UserInfo) user.Info {
	info := &user.DefaultInfo{
		Name:   ui.Username,
		UID:    ui.UID,
		Groups: ui.Groups,
	}
	if len(ui.Extra) > 0 {
		info.Extra = make(map[string][]string, len(ui.Extra))
		for k, v := range ui.Extra {
			info.Extra[k] = v
		}
	}
	return info
}

func (r *liveReviewer) buildReview(token string) *authv1.TokenReview {
	return &authv1.TokenReview{
		Spec: authv1.TokenReviewSpec{
			Token:     token,
			Audiences: r.audiences,
		},
	}
}
