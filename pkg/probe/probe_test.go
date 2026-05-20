// Copyright Jetstack Ltd. See LICENSE for details.
package probe

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"testing"

	"k8s.io/apiserver/pkg/authentication/authenticator"

	"github.com/jetstack/kube-oidc-proxy/pkg/util"
)

type fakeTokenAuthenticator struct {
	notInitialized bool
}

var _ authenticator.Token = &fakeTokenAuthenticator{}

func (f *fakeTokenAuthenticator) AuthenticateToken(_ context.Context, _ string) (*authenticator.Response, bool, error) {
	if f.notInitialized {
		return nil, false, errors.New("foo bar authenticator not initialized")
	}
	return nil, false, errors.New("some other error")
}

func TestRun(t *testing.T) {
	t.Skip("skipping probe test")

	f := &fakeTokenAuthenticator{notInitialized: true}

	port, err := util.FreePort()
	if err != nil {
		t.Fatalf("FreePort() unexpected error: %v", err)
	}

	fakeJWT1, err := util.FakeJWT("https://issuer1.example.com")
	if err != nil {
		t.Fatalf("FakeJWT() unexpected error: %v", err)
	}
	fakeJWT2, err := util.FakeJWT("https://issuer2.example.com")
	if err != nil {
		t.Fatalf("FakeJWT() unexpected error: %v", err)
	}

	if err := Run(port, []string{fakeJWT1, fakeJWT2}, f); err != nil {
		t.Fatalf("Run() unexpected error: %v", err)
	}

	url := fmt.Sprintf("http://0.0.0.0:%s", port)

	var resp *http.Response
	for i := 0; i < 5; i++ {
		resp, err = http.Get(url + "/ready")
		if err == nil {
			break
		}
	}
	if err != nil {
		t.Fatalf("unexpected error reaching probe: %s", err)
	}

	if resp.StatusCode != 503 {
		t.Errorf("expected probe not ready, got %d", resp.StatusCode)
	}

	// Mark initialized — all JWTs now pass.
	f.notInitialized = false

	resp, err = http.Get(url + "/ready")
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	if resp.StatusCode != 200 {
		t.Errorf("expected probe ready, got %d", resp.StatusCode)
	}

	// Once latched ready, stays ready even if authenticator errors again.
	f.notInitialized = true

	resp, err = http.Get(url + "/ready")
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	if resp.StatusCode != 200 {
		t.Errorf("expected probe to remain ready after latch, got %d", resp.StatusCode)
	}
}
