// Copyright Jetstack Ltd. See LICENSE for details.
package proxy

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"go.uber.org/mock/gomock"
	"k8s.io/apiserver/pkg/authentication/authenticator"
	"k8s.io/apiserver/pkg/authentication/user"

	"github.com/rafpe/kube-oidc-proxy/pkg/mocks"
)

// TestReviewToken pins the fail-closed contract of the token-review fallback:
// only an affirmative authenticated result lets a request pass through; a
// missing bearer token, a reviewer error, or an unauthenticated result all
// deny (and the caller then serves 401).
func TestReviewToken(t *testing.T) {
	const bearer = "test-token"

	tests := map[string]struct {
		authHeader string

		// reviewerResult configures the mocked authenticator.Token. When nil,
		// the reviewer must not be called at all.
		reviewerResult func(m *mocks.MockToken)

		expPassthrough bool
	}{
		"no bearer token denies without calling the reviewer": {
			authHeader:     "",
			expPassthrough: false,
		},

		"a reviewer error denies (fail closed)": {
			authHeader: "bearer " + bearer,
			reviewerResult: func(m *mocks.MockToken) {
				m.EXPECT().AuthenticateToken(gomock.Any(), bearer).
					Return(nil, false, errors.New("apiserver unreachable"))
			},
			expPassthrough: false,
		},

		"an unauthenticated result denies": {
			authHeader: "bearer " + bearer,
			reviewerResult: func(m *mocks.MockToken) {
				m.EXPECT().AuthenticateToken(gomock.Any(), bearer).
					Return(nil, false, nil)
			},
			expPassthrough: false,
		},

		"an authenticated result passes through": {
			authHeader: "bearer " + bearer,
			reviewerResult: func(m *mocks.MockToken) {
				m.EXPECT().AuthenticateToken(gomock.Any(), bearer).
					Return(&authenticator.Response{User: &user.DefaultInfo{Name: "user-a"}}, true, nil)
			},
			expPassthrough: true,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			reviewer := mocks.NewMockToken(ctrl)
			if test.reviewerResult != nil {
				test.reviewerResult(reviewer)
			}

			p := &Proxy{tokenReviewer: reviewer}

			req := httptest.NewRequest("GET", "https://target.example.com/foo", nil)
			if test.authHeader != "" {
				req.Header.Set("Authorization", test.authHeader)
			}

			if got := p.reviewToken(httptest.NewRecorder(), req); got != test.expPassthrough {
				t.Errorf("unexpected passthrough decision, exp=%t got=%t", test.expPassthrough, got)
			}
		})
	}
}

// TestWithTokenReviewStatusCodes pins the externally visible contract of the
// token-review handler: every denied path answers 401 without reaching the
// next handler, and only an authenticated review passes the request on.
func TestWithTokenReviewStatusCodes(t *testing.T) {
	const bearer = "test-token"

	tests := map[string]struct {
		tokenReviewEnabled bool
		authHeader         string

		// reviewerResult configures the mocked authenticator.Token. When nil,
		// the reviewer must not be called at all.
		reviewerResult func(m *mocks.MockToken)

		expCode       int
		expNextCalled bool
	}{
		"token review disabled answers 401": {
			tokenReviewEnabled: false,
			authHeader:         "bearer " + bearer,
			expCode:            http.StatusUnauthorized,
		},

		"a missing bearer token answers 401": {
			tokenReviewEnabled: true,
			authHeader:         "",
			expCode:            http.StatusUnauthorized,
		},

		"a reviewer error answers 401 (fail closed)": {
			tokenReviewEnabled: true,
			authHeader:         "bearer " + bearer,
			reviewerResult: func(m *mocks.MockToken) {
				m.EXPECT().AuthenticateToken(gomock.Any(), bearer).
					Return(nil, false, errors.New("apiserver unreachable"))
			},
			expCode: http.StatusUnauthorized,
		},

		"an unauthenticated result answers 401": {
			tokenReviewEnabled: true,
			authHeader:         "bearer " + bearer,
			reviewerResult: func(m *mocks.MockToken) {
				m.EXPECT().AuthenticateToken(gomock.Any(), bearer).
					Return(nil, false, nil)
			},
			expCode: http.StatusUnauthorized,
		},

		"an authenticated result reaches the next handler": {
			tokenReviewEnabled: true,
			authHeader:         "bearer " + bearer,
			reviewerResult: func(m *mocks.MockToken) {
				m.EXPECT().AuthenticateToken(gomock.Any(), bearer).
					Return(&authenticator.Response{User: &user.DefaultInfo{Name: "user-a"}}, true, nil)
			},
			expCode:       http.StatusOK,
			expNextCalled: true,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			reviewer := mocks.NewMockToken(ctrl)
			if test.reviewerResult != nil {
				test.reviewerResult(reviewer)
			}

			p := &Proxy{
				tokenReviewer: reviewer,
				config:        &Config{TokenReview: test.tokenReviewEnabled},
			}
			p.handleError = p.newErrorHandler()

			nextCalled := false
			next := http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
				nextCalled = true
				rw.WriteHeader(http.StatusOK)
			})

			req := httptest.NewRequest("GET", "https://target.example.com/foo", nil)
			if test.authHeader != "" {
				req.Header.Set("Authorization", test.authHeader)
			}

			rec := httptest.NewRecorder()
			p.withTokenReview(next).ServeHTTP(rec, req)

			if rec.Code != test.expCode {
				t.Errorf("unexpected status code, exp=%d got=%d", test.expCode, rec.Code)
			}
			if nextCalled != test.expNextCalled {
				t.Errorf("unexpected next handler invocation, exp=%t got=%t", test.expNextCalled, nextCalled)
			}
		})
	}
}
