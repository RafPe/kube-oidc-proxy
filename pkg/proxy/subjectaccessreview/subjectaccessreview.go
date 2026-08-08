// Copyright Jetstack Ltd. See LICENSE for details.
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

// structure for storing the review data
type SubjectAccessReview struct {
	subjectAccessReviewer clientazv1.SubjectAccessReviewInterface

	// sarTimeout is the single shared budget applied across the whole sequence
	// of SAR checks for one request.
	sarTimeout time.Duration
}

// create a new SubjectAccessReview structure
func New(subjectAccessReviewer clientazv1.SubjectAccessReviewInterface, sarTimeout time.Duration) (*SubjectAccessReview, error) {

	return &SubjectAccessReview{
		subjectAccessReviewer: subjectAccessReviewer,
		sarTimeout:            sarTimeout,
	}, nil
}

// checks the request for impersonation headers, validates that the user is able to perform that impersonation,
// and builds the target object
func (subjectAccessReview *SubjectAccessReview) CheckAuthorizedForImpersonation(req *http.Request, requester user.Info) (user.Info, error) {

	// Derive one shared budget for the whole SAR sequence from the inbound
	// request context, so client cancellation propagates and a stalled API
	// server cannot stall the request indefinitely.
	ctx, cancel := context.WithTimeout(req.Context(), subjectAccessReview.sarTimeout)
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
					result, err := subjectAccessReview.checkRbacImpersonationAuthorization(ctx, "users", userToImpersonate, requester)
					if err != nil {
						return nil, err
					} else {
						if !result {
							return nil, &ImpersonationAuthError{
								Requester: requester.GetName(),
								Kind:      "user",
								Target:    fmt.Sprintf("'%s'", userToImpersonate),
							}
						} else {
							targetUser.Name = userToImpersonate
						}
					}
				}
			} else if keyToCheck == "impersonate-group" {

				for i := range values {
					groupName := values[i]
					result, err := subjectAccessReview.checkRbacImpersonationAuthorization(ctx, "groups", groupName, requester)
					if err != nil {
						return nil, err
					} else {
						if !result {
							return nil, &ImpersonationAuthError{
								Requester: requester.GetName(),
								Kind:      "group",
								Target:    fmt.Sprintf("'%s'", groupName),
							}
						} else {
							targetUser.Groups = append(targetUser.Groups, groupName)
						}
					}
				}
			} else if keyToCheck == "impersonate-uid" {
				uidToImpersonate := values[0]
				result, err := subjectAccessReview.checkRbacImpersonationAuthorization(ctx, "uids", uidToImpersonate, requester)
				if err != nil {
					return nil, err
				} else {
					if !result {
						return nil, &ImpersonationAuthError{
							Requester: requester.GetName(),
							Kind:      "uid",
							Target:    fmt.Sprintf("'%s'", uidToImpersonate),
						}
					} else {
						targetUser.UID = uidToImpersonate
					}
				}
			} else if strings.HasPrefix(keyToCheck, "impersonate-extra-") {
				// according to https://github.com/kubernetes/kubernetes/blob/555623c07eabf22864f6147736fa191e020cca25/staging/src/k8s.io/apiserver/pkg/authentication/user/user.go#L31-L41
				// the extra name MUST be lowercase...so we'll force to lowercase for the rbac check
				extraName := strings.ToLower(key[18:])
				for i := range values {
					result, err := subjectAccessReview.checkRbacImpersonationAuthorization(ctx, "userextras/"+extraName, values[i], requester)
					if err != nil {
						return nil, err
					} else {
						if !result {
							return nil, &ImpersonationAuthError{
								Requester: requester.GetName(),
								Kind:      "extra info",
								Target:    fmt.Sprintf("'%s'='%s'", extraName, values[i]),
							}
						} else {
							infoVals, ok := targetUser.Extra[extraName]

							if !ok {
								infoVals = make([]string, 0)

							}

							infoVals = append(infoVals, values[i])
							targetUser.Extra[extraName] = infoVals
						}
					}
				}
			} else if strings.HasPrefix(keyToCheck, "impersonate-") {
				// unkown impersonation header, fail
				return nil, fmt.Errorf("unknown impersonation header '%s'", key)
			}

		}

	}

	if hasImpersonation {

		// first clearing out the old headers
		newHeaders := http.Header{}

		for k := range req.Header {
			if _, ok := headersToRemove[k]; !ok {
				for _, v := range req.Header.Values(k) {
					newHeaders.Add(k, v)
				}
			}
		}

		//haven't errored out, but has impersonation - returning target user
		req.Header = newHeaders

		return targetUser, nil
	} else {
		//no impersonation, no user to return
		return nil, nil
	}
}

// submit a SubjectAccessReview request to the API server to validate that impersonation can occur
func (subjectAccessReview *SubjectAccessReview) checkRbacImpersonationAuthorization(ctx context.Context, resource string, name string, requester user.Info) (bool, error) {
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

	reviewResult, err := subjectAccessReview.subjectAccessReviewer.Create(ctx, &clusterSubjectAccessReview, metav1.CreateOptions{})

	if err != nil {
		return false, fmt.Errorf("%w: %w", ErrCreateSubjectAccessReview, err)
	} else {
		return reviewResult.Status.Allowed, nil
	}
}
