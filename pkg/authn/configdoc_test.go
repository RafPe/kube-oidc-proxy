// Copyright Jetstack Ltd. See LICENSE for details.
package authn

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	apiserver "k8s.io/apiserver/pkg/apis/apiserver"
	apiserverv1 "k8s.io/apiserver/pkg/apis/apiserver/v1"
	"sigs.k8s.io/yaml"

	"github.com/rafpe/kube-oidc-proxy/pkg/authn/v1alpha1"
)

// The tests make each configuration document from Go values and marshal it
// to YAML. A test then compares every loaded entry with the value that it
// expects. A document that Go values cannot express, such as a duplicate
// key, is the only document that a test writes as text.

// testJWT returns a v1 JWT authenticator that maps the sub claim to the
// username with prefix. With more than one audience, it sets
// audienceMatchPolicy to MatchAny, because upstream validation requires it.
func testJWT(url, prefix string, audiences ...string) apiserverv1.JWTAuthenticator {
	jwt := apiserverv1.JWTAuthenticator{
		Issuer: apiserverv1.Issuer{URL: url, Audiences: audiences},
		ClaimMappings: apiserverv1.ClaimMappings{
			Username: apiserverv1.PrefixedClaimOrExpression{Claim: "sub", Prefix: &prefix},
		},
	}
	if len(audiences) > 1 {
		jwt.Issuer.AudienceMatchPolicy = apiserverv1.AudienceMatchPolicyMatchAny
	}
	return jwt
}

// wantJWT returns the internal JWT authenticator that LoadConfiguration must
// return for testJWT(url, prefix, audiences...).
func wantJWT(url, prefix string, audiences ...string) apiserver.JWTAuthenticator {
	jwt := apiserver.JWTAuthenticator{
		Issuer: apiserver.Issuer{URL: url, Audiences: audiences},
		ClaimMappings: apiserver.ClaimMappings{
			Username: apiserver.PrefixedClaimOrExpression{Claim: "sub", Prefix: &prefix},
		},
	}
	if len(audiences) > 1 {
		jwt.Issuer.AudienceMatchPolicy = apiserver.AudienceMatchPolicyMatchAny
	}
	return jwt
}

// upstreamDoc returns an apiserver.config.k8s.io/v1 document with jwts.
func upstreamDoc(jwts ...apiserverv1.JWTAuthenticator) apiserverv1.AuthenticationConfiguration {
	if jwts == nil {
		jwts = []apiserverv1.JWTAuthenticator{}
	}
	return apiserverv1.AuthenticationConfiguration{
		TypeMeta: metav1.TypeMeta{APIVersion: apiserverv1.SchemeGroupVersion.String(), Kind: v1alpha1.Kind},
		JWT:      jwts,
	}
}

// proxyIssuer returns an issuer of the proxy kind. Its username prefix is
// name followed by a colon.
func proxyIssuer(name, url string, audiences ...string) v1alpha1.Issuer {
	return v1alpha1.Issuer{Name: name, JWT: testJWT(url, name+":", audiences...)}
}

// wantProxyEntry returns the Entry that LoadConfiguration must return for
// proxyIssuer(name, url, audiences...).
func wantProxyEntry(name, url string, audiences ...string) Entry {
	return Entry{Name: name, JWT: wantJWT(url, name+":", audiences...)}
}

// proxyDoc returns a kube-oidc-proxy.rafpe.github.io/v1alpha1 document with
// issuers.
func proxyDoc(issuers ...v1alpha1.Issuer) v1alpha1.AuthenticationConfiguration {
	if issuers == nil {
		issuers = []v1alpha1.Issuer{}
	}
	return v1alpha1.AuthenticationConfiguration{
		TypeMeta: metav1.TypeMeta{APIVersion: v1alpha1.APIVersion, Kind: v1alpha1.Kind},
		Issuers:  issuers,
	}
}

// marshalDoc returns doc as YAML.
func marshalDoc(t *testing.T, doc any) []byte {
	t.Helper()
	data, err := yaml.Marshal(doc)
	if err != nil {
		t.Fatalf("marshaling the configuration document: %v", err)
	}
	return data
}

// editDoc returns doc as YAML after edit changes its generic map form. A
// test uses it to add a field that the Go types do not have.
func editDoc(t *testing.T, doc any, edit func(m map[string]any)) []byte {
	t.Helper()
	data, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshaling the configuration document: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("decoding the configuration document: %v", err)
	}
	edit(m)
	return marshalDoc(t, m)
}

// firstJWT returns the jwt map of issuers[0] of a proxy document in its
// generic map form.
func firstJWT(m map[string]any) map[string]any {
	return m["issuers"].([]any)[0].(map[string]any)["jwt"].(map[string]any)
}

// writeDoc writes data to a file in a test directory and returns the path.
func writeDoc(t *testing.T, data []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "auth.yaml")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
