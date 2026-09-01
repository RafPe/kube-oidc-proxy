// Copyright Jetstack Ltd. See LICENSE for details.

// Package subjectaccessreview authorizes impersonation requests by submitting
// SubjectAccessReviews to the API server. It exposes typed, sentinel-backed
// errors so HTTP handlers can select a response status via errors.Is rather
// than by matching message text.
package subjectaccessreview

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	v1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apiserver/pkg/authentication/user"
	clientazv1 "k8s.io/client-go/kubernetes/typed/authorization/v1"
)

var (
	ErrorNoImpersonationUserFound = errors.New("no Impersonation-User header found for request")

	// ErrCreateSubjectAccessReview is the sentinel wrapping a failure to submit a
	// SubjectAccessReview to the API server. Callers can match it with errors.Is;
	// the underlying error (including context.Canceled/DeadlineExceeded) is wrapped
	// alongside it so it remains detectable too.
	ErrCreateSubjectAccessReview = errors.New("create SubjectAccessReview")

	// ErrImpersonationNotAllowed is the sentinel that classifies an authorization
	// denial: the requester is not permitted to impersonate a requested resource.
	// Every denial returned by CheckAuthorizedForImpersonation is an
	// *ImpersonationAuthError, which matches this sentinel via errors.Is. HTTP
	// handlers select a 403 with errors.Is(err, ErrImpersonationNotAllowed)
	// instead of matching on message text.
	ErrImpersonationNotAllowed = errors.New("not allowed to impersonate")

	// ErrTooManyImpersonationHeaderValues is the sentinel that classifies a
	// request carrying more impersonation header values than the configured cap.
	// Each value costs one SubjectAccessReview round trip to the API server, so
	// the count is capped before any review is sent. HTTP handlers select a 431
	// with errors.Is; this is not an authorization decision, so it deliberately
	// does not classify as ErrImpersonationNotAllowed.
	ErrTooManyImpersonationHeaderValues = errors.New("too many impersonation header values")
)

// ImpersonationAuthError reports that a requester is not authorized to
// impersonate a particular resource (user, group, uid, or extra info). It
// classifies as ErrImpersonationNotAllowed through errors.Is so callers can
// select an HTTP 403 without inspecting the message string, while Error()
// preserves the human-readable, client-facing wording.
type ImpersonationAuthError struct {
	// Requester is the name of the authenticated user attempting impersonation.
	Requester string

	// Kind is the impersonated resource kind as rendered in the message, e.g.
	// "user", "group", "uid", or "extra info".
	Kind string

	// Target is the quoted resource identifier as rendered in the message, e.g.
	// "'a-user'" or "'foo'='bar'".
	Target string
}

func (e *ImpersonationAuthError) Error() string {
	return fmt.Sprintf("%s is not allowed to impersonate %s %s", e.Requester, e.Kind, e.Target)
}

// Is reports whether e should be treated as ErrImpersonationNotAllowed, letting
// errors.Is classify any denial regardless of the concrete resource involved.
func (e *ImpersonationAuthError) Is(target error) bool {
	return target == ErrImpersonationNotAllowed
}

// DefaultTimeout is the default value for the SAR authorization budget. It
// bounds the total time spent authorizing a single request's impersonation via
// SubjectAccessReviews. It covers the whole sequence of checks, not each call,
// so a stalled API server cannot hold a client connection open indefinitely
// (the SAR client inherits rest.Config.Timeout, which defaults to zero).
const DefaultTimeout = 5 * time.Second

// DefaultMaxHeaderValues is the default cap on the total number of
// impersonation header values accepted per request (one Impersonate-User plus
// every Impersonate-Group, Impersonate-Uid and Impersonate-Extra-* value).
// Each value costs one serial SubjectAccessReview round trip to the API
// server, so the count bounds the per-request amplification a client can
// drive. kube-apiserver itself places no count limit on impersonation values
// (only its ~1MiB total header size limit applies, which admits thousands of
// values), but its per-value authorization is an in-process check, not a
// network call. 64 comfortably covers realistic clients — kubectl --as/
// --as-group sends a handful of values, and programmatic identity forwarding
// rarely exceeds a few dozen groups — while keeping the worst case at 64
// round trips inside the shared timeout budget.
const DefaultMaxHeaderValues = 64

// SubjectAccessReview authorizes impersonation requests by submitting a
// SubjectAccessReview to the API server for each impersonated resource. A
// single shared timeout budget bounds the whole sequence of checks performed
// for one request.
type SubjectAccessReview struct {
	reviewer clientazv1.SubjectAccessReviewInterface

	// sarTimeout is the single shared budget applied across the whole sequence
	// of SAR checks for one request.
	sarTimeout time.Duration

	// maxHeaderValues caps the total number of impersonation header values a
	// single request may carry. Requests over the cap are rejected before any
	// SAR is sent.
	maxHeaderValues int
}

// New returns a SubjectAccessReview that authorizes impersonation via reviewer,
// bounding the whole sequence of checks for a single request by sarTimeout and
// refusing requests that carry more than maxHeaderValues impersonation header
// values. maxHeaderValues must be greater than zero: every SAR costs a round
// trip, so an unbounded value count must not be constructible.
func New(reviewer clientazv1.SubjectAccessReviewInterface, sarTimeout time.Duration, maxHeaderValues int) (*SubjectAccessReview, error) {
	if maxHeaderValues <= 0 {
		return nil, fmt.Errorf("maxHeaderValues must be greater than 0, got %d", maxHeaderValues)
	}
	return &SubjectAccessReview{
		reviewer:        reviewer,
		sarTimeout:      sarTimeout,
		maxHeaderValues: maxHeaderValues,
	}, nil
}

// CheckAuthorizedForImpersonation inspects the request's impersonation headers,
// verifies via SubjectAccessReview that requester is allowed to impersonate
// each requested target, and returns the resulting impersonated user. It
// returns a nil user.Info when the request carries no impersonation headers. An
// authorization denial is returned as an *ImpersonationAuthError, which matches
// ErrImpersonationNotAllowed via errors.Is.
func (s *SubjectAccessReview) CheckAuthorizedForImpersonation(req *http.Request, requester user.Info) (user.Info, error) {
	// Refuse over-wide requests before spending anything: every impersonation
	// header value below costs one serial SAR round trip, and the value count
	// is entirely client-controlled. Counting mirrors the consumption loop
	// (case-insensitive Impersonate- prefix over every key's values), so no
	// header-case variant or duplicate key can be consumed without having been
	// counted.
	if count := countImpersonationHeaderValues(req.Header); count > s.maxHeaderValues {
		return nil, fmt.Errorf("%w: request carries %d impersonation header values, the limit is %d",
			ErrTooManyImpersonationHeaderValues, count, s.maxHeaderValues)
	}

	// Derive one shared budget for the whole SAR sequence from the inbound
	// request context, so client cancellation propagates and a stalled API
	// server cannot stall the request indefinitely.
	ctx, cancel := context.WithTimeout(req.Context(), s.sarTimeout)
	defer cancel()

	impersonatedUser := req.Header.Get("impersonate-user")

	hasImpersonatedUser := impersonatedUser != ""

	hasImpersonation := false

	targetUser := &user.DefaultInfo{
		Name:   "",
		Groups: make([]string, 0),
		Extra:  map[string][]string{},
		UID:    "",
	}

	headersToRemove := make(map[string]string)

	for key, values := range req.Header {
		keyToCheck := strings.ToLower(key)
		if strings.HasPrefix(keyToCheck, "impersonate-") {
			if !hasImpersonatedUser {
				// found impersonation header, but not a user
				return nil, ErrorNoImpersonationUserFound
			}

			headersToRemove[key] = key
			hasImpersonation = true
			if keyToCheck == "impersonate-user" {
				userToImpersonate := values[0]
				if userToImpersonate != "" {
					result, err := s.checkRbacImpersonationAuthorization(ctx, "users", userToImpersonate, requester)
					if err != nil {
						return nil, err
					}
					if !result {
						return nil, &ImpersonationAuthError{
							Requester: requester.GetName(),
							Kind:      "user",
							Target:    fmt.Sprintf("'%s'", userToImpersonate),
						}
					}
					targetUser.Name = userToImpersonate
				}
			} else if keyToCheck == "impersonate-group" {
				for i := range values {
					groupName := values[i]
					result, err := s.checkRbacImpersonationAuthorization(ctx, "groups", groupName, requester)
					if err != nil {
						return nil, err
					}
					if !result {
						return nil, &ImpersonationAuthError{
							Requester: requester.GetName(),
							Kind:      "group",
							Target:    fmt.Sprintf("'%s'", groupName),
						}
					}
					targetUser.Groups = append(targetUser.Groups, groupName)
				}
			} else if keyToCheck == "impersonate-uid" {
				uidToImpersonate := values[0]
				result, err := s.checkRbacImpersonationAuthorization(ctx, "uids", uidToImpersonate, requester)
				if err != nil {
					return nil, err
				}
				if !result {
					return nil, &ImpersonationAuthError{
						Requester: requester.GetName(),
						Kind:      "uid",
						Target:    fmt.Sprintf("'%s'", uidToImpersonate),
					}
				}
				targetUser.UID = uidToImpersonate
			} else if strings.HasPrefix(keyToCheck, "impersonate-extra-") {
				// according to https://github.com/kubernetes/kubernetes/blob/555623c07eabf22864f6147736fa191e020cca25/staging/src/k8s.io/apiserver/pkg/authentication/user/user.go#L31-L41
				// the extra name MUST be lowercase...so we'll force to lowercase for the rbac check
				extraName := strings.ToLower(key[18:])
				for i := range values {
					result, err := s.checkRbacImpersonationAuthorization(ctx, "userextras/"+extraName, values[i], requester)
					if err != nil {
						return nil, err
					}
					if !result {
						return nil, &ImpersonationAuthError{
							Requester: requester.GetName(),
							Kind:      "extra info",
							Target:    fmt.Sprintf("'%s'='%s'", extraName, values[i]),
						}
					}
					targetUser.Extra[extraName] = append(targetUser.Extra[extraName], values[i])
				}
			} else if strings.HasPrefix(keyToCheck, "impersonate-") {
				// unknown impersonation header, fail
				return nil, fmt.Errorf("unknown impersonation header '%s'", key)
			}

		}

	}

	if !hasImpersonation {
		// no impersonation, no user to return
		return nil, nil
	}

	// Clear out the impersonation headers we consumed before forwarding.
	newHeaders := http.Header{}
	for k := range req.Header {
		if _, ok := headersToRemove[k]; !ok {
			for _, v := range req.Header.Values(k) {
				newHeaders.Add(k, v)
			}
		}
	}

	// Authorized: forward the request with the impersonation target.
	req.Header = newHeaders
	return targetUser, nil
}

// countImpersonationHeaderValues returns the total number of impersonation
// header values the request carries: every value of every header whose key
// matches the Impersonate- prefix case-insensitively, exactly as the
// consumption loop in CheckAuthorizedForImpersonation matches them.
func countImpersonationHeaderValues(headers http.Header) int {
	count := 0
	for key, values := range headers {
		if strings.HasPrefix(strings.ToLower(key), "impersonate-") {
			count += len(values)
		}
	}
	return count
}

// checkRbacImpersonationAuthorization submits a SubjectAccessReview to the API
// server to validate that requester may impersonate the named resource. It
// reports whether the review allowed the request.
func (s *SubjectAccessReview) checkRbacImpersonationAuthorization(ctx context.Context, resource string, name string, requester user.Info) (bool, error) {
	extras := map[string]v1.ExtraValue{}
	var group string
	var subresource string

	for key, value := range requester.GetExtra() {
		extras[key] = value
	}

	slashIndex := strings.Index(resource, "/")

	if slashIndex > 0 {
		newResources := strings.Split(resource, "/")
		resource = newResources[0]
		subresource = newResources[1]
		group = "authentication.k8s.io"
	}

	// UID impersonation lives in authentication.k8s.io, unlike
	// users/groups/serviceaccounts which are core. Without the group the
	// review checks a core-group "uids" resource no RBAC rule grants.
	if resource == "uids" {
		group = "authentication.k8s.io"
	}

	clusterSubjectAccessReview := v1.SubjectAccessReview{
		Spec: v1.SubjectAccessReviewSpec{
			User:   requester.GetName(),
			Groups: requester.GetGroups(),
			Extra:  extras,

			ResourceAttributes: &v1.ResourceAttributes{
				Verb:        "impersonate",
				Group:       group,
				Resource:    resource,
				Subresource: subresource,
				Name:        name,
			},
		},
	}

	reviewResult, err := s.reviewer.Create(ctx, &clusterSubjectAccessReview, metav1.CreateOptions{})
	if err != nil {
		return false, fmt.Errorf("%w: %w", ErrCreateSubjectAccessReview, err)
	}
	return reviewResult.Status.Allowed, nil
}
