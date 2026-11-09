// Copyright Jetstack Ltd. See LICENSE for details.

// Package fake provides a stub SubjectAccessReviewInterface for use in tests.
package fake

import (
	"context"

	azv1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	clientazv1 "k8s.io/client-go/kubernetes/typed/authorization/v1"
)

var _ clientazv1.SubjectAccessReviewInterface = &Reviewer{}

// Reviewer is a fixed-policy SubjectAccessReviewInterface: it allows a small,
// hard-coded set of impersonation targets the package tests use (user
// jjackson, group group3, uid 1-2-3-4, extra remoteaddr=1.2.3.4) and denies
// everything else, or fails every review with the error it was built with.
type Reviewer struct {
	err error
}

// New returns a Reviewer that fails every review with err, or applies its fixed
// policy when err is nil.
func New(err error) *Reviewer {
	return &Reviewer{
		err: err,
	}
}

// Create implements SubjectAccessReviewInterface.
func (f *Reviewer) Create(ctx context.Context, req *azv1.SubjectAccessReview, co metav1.CreateOptions) (*azv1.SubjectAccessReview, error) {
	if f.err != nil {
		return nil, f.err
	}

	if req.Spec.ResourceAttributes.Resource == "users" && req.Spec.ResourceAttributes.Name == "jjackson" {
		req.Status = azv1.SubjectAccessReviewStatus{
			Allowed: true,
		}

		return req, nil
	}

	if req.Spec.ResourceAttributes.Resource == "groups" && req.Spec.ResourceAttributes.Name == "group3" {
		req.Status = azv1.SubjectAccessReviewStatus{
			Allowed: true,
		}

		return req, nil
	}

	// UID impersonation is authorized in the authentication.k8s.io group,
	// unlike users/groups which are core. Refusing a group-less review here
	// pins the group the production SAR must send.
	if req.Spec.ResourceAttributes.Group == "authentication.k8s.io" &&
		req.Spec.ResourceAttributes.Resource == "uids" &&
		req.Spec.ResourceAttributes.Name == "1-2-3-4" {
		req.Status = azv1.SubjectAccessReviewStatus{
			Allowed: true,
		}

		return req, nil
	}

	if req.Spec.ResourceAttributes.Resource == "userextras" && req.Spec.ResourceAttributes.Subresource == "remoteaddr" && req.Spec.ResourceAttributes.Name == "1.2.3.4" {
		req.Status = azv1.SubjectAccessReviewStatus{
			Allowed: true,
		}

		return req, nil
	}

	// Anything outside the fixed policy is denied.
	req.Status = azv1.SubjectAccessReviewStatus{
		Allowed: false,
	}

	return req, nil

}
