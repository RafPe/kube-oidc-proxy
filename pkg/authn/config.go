// Copyright Jetstack Ltd. See LICENSE for details.
package authn

import (
	"fmt"
	"os"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	apiserver "k8s.io/apiserver/pkg/apis/apiserver"
	"k8s.io/apiserver/pkg/apis/apiserver/install"
	"k8s.io/apiserver/pkg/apis/apiserver/validation"
	authenticationcel "k8s.io/apiserver/pkg/authentication/cel"
)

var (
	authConfigScheme = runtime.NewScheme()
	authConfigCodecs = serializer.NewCodecFactory(authConfigScheme, serializer.EnableStrict)
)

func init() {
	install.Install(authConfigScheme)
}

// LoadConfiguration reads, strictly decodes (v1 or v1beta1), converts to the
// internal type and validates the whole AuthenticationConfiguration document
// at path. Validation compiles every CEL expression with the given compiler
// and rejects duplicate issuers across entries.
func LoadConfiguration(path string, compiler authenticationcel.Compiler) (*apiserver.AuthenticationConfiguration, error) {
	// path is the operator's own --authentication-config flag, not request input.
	data, err := os.ReadFile(path) //nolint:gosec // G304: operator-supplied path
	if err != nil {
		return nil, fmt.Errorf("reading authentication-config %q: %w", path, err)
	}

	obj, gvk, err := authConfigCodecs.UniversalDecoder().Decode(data, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("parsing authentication-config %q: %w", path, err)
	}

	cfg, ok := obj.(*apiserver.AuthenticationConfiguration)
	if !ok {
		return nil, fmt.Errorf("authentication-config %q: expected AuthenticationConfiguration, got %s", path, gvk)
	}

	if cfg.Anonymous != nil {
		return nil, fmt.Errorf("authentication-config %q: the 'anonymous' section is not supported by kube-oidc-proxy", path)
	}

	if len(cfg.JWT) == 0 {
		return nil, fmt.Errorf("authentication-config %q: jwt list must not be empty", path)
	}

	// disallowedIssuers is nil: that parameter exists for kube-apiserver to
	// reserve its own service-account issuer, which does not apply to the proxy.
	if errs := validation.ValidateAuthenticationConfiguration(compiler, cfg, nil).ToAggregate(); errs != nil {
		return nil, fmt.Errorf("invalid authentication-config %q: %w", path, errs)
	}

	return cfg, nil
}
