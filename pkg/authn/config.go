// Copyright Jetstack Ltd. See LICENSE for details.
package authn

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/apimachinery/pkg/util/sets"
	k8svalidation "k8s.io/apimachinery/pkg/util/validation"
	apiserver "k8s.io/apiserver/pkg/apis/apiserver"
	"k8s.io/apiserver/pkg/apis/apiserver/install"
	apiserverv1 "k8s.io/apiserver/pkg/apis/apiserver/v1"
	"k8s.io/apiserver/pkg/apis/apiserver/validation"
	authenticationcel "k8s.io/apiserver/pkg/authentication/cel"
	"sigs.k8s.io/yaml"

	"github.com/rafpe/kube-oidc-proxy/pkg/authn/v1alpha1"
)

// maxIssuers is the issuer limit of the upstream AuthenticationConfiguration.
// The proxy kind uses the same limit.
const maxIssuers = 64

var (
	authConfigScheme = runtime.NewScheme()
	authConfigCodecs = serializer.NewCodecFactory(authConfigScheme, serializer.EnableStrict)
)

func init() {
	install.Install(authConfigScheme)
}

// Configuration is a decoded authentication configuration of either kind.
type Configuration struct {
	// ProxyKind is true for a kube-oidc-proxy.rafpe.github.io document. The
	// entry names then come from the document. For the upstream kind, each
	// entry name is the host of its issuer URL.
	ProxyKind bool

	// Entries are the issuers in configuration order.
	Entries []Entry
}

// Entry is one issuer of a Configuration.
type Entry struct {
	// Name is the issuer_name of the issuer.
	Name string

	// JWT is the validated JWT authenticator configuration of the issuer.
	JWT apiserver.JWTAuthenticator
}

// LoadConfiguration reads the authentication configuration at path, decodes
// it strictly and validates it. The apiVersion of the document selects the
// kind:
//
//   - kube-oidc-proxy.rafpe.github.io/v1alpha1: the proxy kind. See
//     loadProxyConfiguration.
//   - any other value: the upstream apiserver.config.k8s.io kind, v1 or
//     v1beta1. Validation compiles every CEL expression with compiler and
//     refuses duplicate issuers across entries.
func LoadConfiguration(path string, compiler authenticationcel.Compiler) (*Configuration, error) {
	// path is the operator's own --authentication-config flag, not request input.
	data, err := os.ReadFile(path) //nolint:gosec // G304: operator-supplied path
	if err != nil {
		return nil, fmt.Errorf("reading authentication-config %q: %w", path, err)
	}

	// A document that does not decode as YAML goes to the upstream decoder,
	// which reports the parse error.
	var meta metav1.TypeMeta
	if err := yaml.Unmarshal(data, &meta); err == nil && meta.APIVersion == v1alpha1.APIVersion {
		return loadProxyConfiguration(path, data, compiler)
	}
	return loadUpstreamConfiguration(path, data, compiler)
}

// loadUpstreamConfiguration decodes and validates an upstream
// AuthenticationConfiguration. The name of each entry is the host of its
// issuer URL.
func loadUpstreamConfiguration(path string, data []byte, compiler authenticationcel.Compiler) (*Configuration, error) {
	cfg, err := decodeUpstream(data)
	if err != nil {
		return nil, fmt.Errorf("authentication-config %q: %w", path, err)
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

	entries := make([]Entry, 0, len(cfg.JWT))
	for _, jwt := range cfg.JWT {
		entries = append(entries, Entry{Name: IssuerName(jwt.Issuer.URL), JWT: jwt})
	}
	return &Configuration{Entries: entries}, nil
}

// decodeUpstream strictly decodes an upstream AuthenticationConfiguration
// document, v1 or v1beta1, into the internal type.
func decodeUpstream(data []byte) (*apiserver.AuthenticationConfiguration, error) {
	obj, gvk, err := authConfigCodecs.UniversalDecoder().Decode(data, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("parsing: %w", err)
	}
	cfg, ok := obj.(*apiserver.AuthenticationConfiguration)
	if !ok {
		return nil, fmt.Errorf("expected AuthenticationConfiguration, got %s", gvk)
	}
	return cfg, nil
}

// loadProxyConfiguration decodes and validates a kube-oidc-proxy.rafpe.github.io
// AuthenticationConfiguration. It runs these steps in this order:
//
//  1. Decode the document strictly. An unknown field is an error.
//  2. For each issuer, validate the name and run the upstream decoding and
//     validation on a document that contains only that issuer.
//  3. Refuse two issuers with the same name.
//  4. Refuse two issuers with the same issuer URL and a shared audience.
//  5. Refuse two issuers with the same non-empty discoveryURL.
//
// The errors name an issuer by its index, as issuers[i]. The errors that this
// function makes do not contain an issuer URL.
func loadProxyConfiguration(path string, data []byte, compiler authenticationcel.Compiler) (*Configuration, error) {
	var doc v1alpha1.AuthenticationConfiguration
	if err := yaml.UnmarshalStrict(data, &doc); err != nil {
		return nil, fmt.Errorf("parsing authentication-config %q: %w", path, err)
	}
	if doc.Kind != v1alpha1.Kind {
		return nil, fmt.Errorf("authentication-config %q: expected AuthenticationConfiguration, got %s", path, doc.Kind)
	}
	if len(doc.Issuers) == 0 {
		return nil, fmt.Errorf("authentication-config %q: issuers list must not be empty", path)
	}
	if len(doc.Issuers) > maxIssuers {
		return nil, fmt.Errorf("authentication-config %q: issuers list has %d entries, the limit is %d", path, len(doc.Issuers), maxIssuers)
	}

	entries := make([]Entry, 0, len(doc.Issuers))
	for i, iss := range doc.Issuers {
		if msgs := k8svalidation.IsDNS1123Subdomain(iss.Name); len(msgs) > 0 {
			return nil, fmt.Errorf("invalid authentication-config %q: issuers[%d].name %q: %s", path, i, iss.Name, strings.Join(msgs, ", "))
		}
		jwt, err := validateJWT(iss.JWT, compiler)
		if err != nil {
			return nil, fmt.Errorf("invalid authentication-config %q: issuers[%d]: %w", path, i, err)
		}
		entries = append(entries, Entry{Name: iss.Name, JWT: jwt})
	}

	if err := checkAcrossIssuers(entries); err != nil {
		return nil, fmt.Errorf("invalid authentication-config %q: %w", path, err)
	}
	return &Configuration{ProxyKind: true, Entries: entries}, nil
}

// validateJWT runs the upstream decoding and validation on a document that
// contains only jwt. The upstream decoding applies the defaults and the
// conversion to the internal type that an upstream document gets.
func validateJWT(jwt apiserverv1.JWTAuthenticator, compiler authenticationcel.Compiler) (apiserver.JWTAuthenticator, error) {
	single := apiserverv1.AuthenticationConfiguration{
		TypeMeta: metav1.TypeMeta{APIVersion: apiserverv1.SchemeGroupVersion.String(), Kind: v1alpha1.Kind},
		JWT:      []apiserverv1.JWTAuthenticator{jwt},
	}
	data, err := json.Marshal(single)
	if err != nil {
		return apiserver.JWTAuthenticator{}, err
	}
	cfg, err := decodeUpstream(data)
	if err != nil {
		return apiserver.JWTAuthenticator{}, err
	}
	if errs := validation.ValidateAuthenticationConfiguration(compiler, cfg, nil).ToAggregate(); errs != nil {
		return apiserver.JWTAuthenticator{}, errs
	}
	return cfg.JWT[0], nil
}

// checkAcrossIssuers compares each pair of issuers of the proxy kind. It
// refuses a shared name, a shared audience for one issuer URL, and a shared
// discovery URL.
func checkAcrossIssuers(entries []Entry) error {
	for i := range entries {
		for j := i + 1; j < len(entries); j++ {
			a, b := entries[i], entries[j]
			if a.Name == b.Name {
				return fmt.Errorf("issuers[%d] and issuers[%d] have the same name %q", i, j, a.Name)
			}
			if a.JWT.Issuer.URL == b.JWT.Issuer.URL {
				shared := sets.New(a.JWT.Issuer.Audiences...).Intersection(sets.New(b.JWT.Issuer.Audiences...))
				if shared.Len() > 0 {
					return fmt.Errorf("issuers[%d] and issuers[%d] have the same issuer URL and share the audience %q", i, j, sets.List(shared)[0])
				}
			}
			if a.JWT.Issuer.DiscoveryURL != "" && a.JWT.Issuer.DiscoveryURL == b.JWT.Issuer.DiscoveryURL {
				return fmt.Errorf("issuers[%d] and issuers[%d] have the same discoveryURL", i, j)
			}
		}
	}
	return nil
}
