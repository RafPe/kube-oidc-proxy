// Copyright Jetstack Ltd. See LICENSE for details.
package authn

import (
	"context"
	"errors"
	"testing"

	"go.uber.org/mock/gomock"
	"k8s.io/apiserver/pkg/authentication/authenticator"
	authuser "k8s.io/apiserver/pkg/authentication/user"

	"github.com/rafpe/kube-oidc-proxy/pkg/authn/authntest"
)

// TestAttributeToIssuerAttributesOnlyAcceptedTokens pins what the wrapper reports.
// A rejected or errored token was not accepted by this issuer, so naming it
// would attribute a request to an issuer that refused it.
func TestAttributeToIssuerAttributesOnlyAcceptedTokens(t *testing.T) {
	accepted := &authenticator.Response{User: &authuser.DefaultInfo{Name: "alice"}}

	tests := map[string]struct {
		resp *authenticator.Response
		ok   bool
		err  error
		want string
	}{
		"accepted token is attributed": {resp: accepted, ok: true, want: "corp"},
		"rejected token is not":        {},
		"errored token is not":         {err: errors.New("token is expired")},
		"error alongside ok is not":    {resp: accepted, ok: true, err: errors.New("token is expired")},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			inner := authntest.NewMockToken(ctrl)
			inner.EXPECT().AuthenticateToken(gomock.Any(), "fake-token").Return(test.resp, test.ok, test.err)

			ctx, holder := WithIssuerHolder(context.Background())
			if _, _, err := AttributeToIssuer("corp", inner).AuthenticateToken(ctx, "fake-token"); !errors.Is(err, test.err) {
				t.Fatalf("AuthenticateToken error = %v, want %v", err, test.err)
			}

			if holder.Name() != test.want {
				t.Errorf("issuer name = %q, want %q", holder.Name(), test.want)
			}
		})
	}
}

// TestRecordIssuerWithoutHolderIsNoOp covers the callers that authenticate a
// token outside the request chain — the readiness probe drives the same
// wrapped authenticator with a fake JWT — where no holder was ever placed on
// the context.
func TestRecordIssuerWithoutHolderIsNoOp(t *testing.T) {
	RecordIssuer(context.Background(), "corp")
}
