// Copyright Jetstack Ltd. See LICENSE for details.
package authconfig

import (
	"context"
	"encoding/json"
	"net/url"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	apiserverv1 "k8s.io/apiserver/pkg/apis/apiserver/v1"
	"sigs.k8s.io/yaml"

	"github.com/rafpe/kube-oidc-proxy/test/e2e/framework"
	"github.com/rafpe/kube-oidc-proxy/test/e2e/suite/cases/sharedtests"
	"github.com/rafpe/kube-oidc-proxy/test/util"
)

const (
	issuer2Name      = "oidc-issuer2-e2e"
	authConfigVolume = "auth-config"
	authConfigKey    = "config.yaml"

	// issuer2ExtraAudience is a second audience accepted for the second
	// issuer only, so a token carrying it alone proves audienceMatchPolicy
	// MatchAny and that audiences are scoped per issuer.
	issuer2ExtraAudience = "issuer2-secondary-audience"
)

// Every spec here reads through the same AuthenticationConfiguration proxy
// deployment and mutates no cluster state, so they all share a single deploy.
var _ = framework.CasesDescribe("AuthenticationConfiguration multi-issuer", Ordered, ContinueOnFailure, Label("shard-b"), func() {
	f := framework.NewOrderedDefaultFramework("authconfig")

	var (
		issuer2Bundle *util.KeyBundle
		issuer2URL    *url.URL
	)

	f.BeforeProxyDeploy = func() {
		var err error

		By("Deploying second OIDC issuer")
		issuer2Bundle, issuer2URL, err = f.Helper().DeployNamedIssuer(f.Namespace.Name, issuer2Name)
		Expect(err).NotTo(HaveOccurred())

		By("Creating AuthenticationConfiguration ConfigMap")
		cfgYAML, err := yaml.Marshal(authConfig(
			jwtAuthenticator(f.IssuerURL().String(), f.IssuerKeyBundle().CertBytes, f.ClientID()),
			jwtAuthenticator(issuer2URL.String(), issuer2Bundle.CertBytes, f.ClientID(), issuer2ExtraAudience),
		))
		Expect(err).NotTo(HaveOccurred())

		_, err = f.KubeClientSet.CoreV1().ConfigMaps(f.Namespace.Name).Create(
			context.TODO(),
			&corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{Name: authConfigVolume},
				Data:       map[string]string{authConfigKey: string(cfgYAML)},
			},
			metav1.CreateOptions{},
		)
		Expect(err).NotTo(HaveOccurred())

		f.ExtraProxyVolumes = []corev1.Volume{configMapVolume(authConfigVolume)}
		f.ExtraProxyArgs = []string{"--authentication-config=/" + authConfigVolume + "/" + authConfigKey}
	}

	sharedtests.RunTokenValidationTests(f)

	It("accepts a valid token from the second configured issuer", func() {
		payload := f.Helper().NewTokenPayload(issuer2URL, f.ClientID(), time.Now().Add(time.Minute))
		sharedtests.ExpectProxyAuthenticated(f, issuer2Bundle, payload)
	})

	It("accepts a token carrying only the issuer's second audience (audienceMatchPolicy MatchAny)", func() {
		payload := tokenPayloadWithAudiences(issuer2URL, []string{issuer2ExtraAudience})
		sharedtests.ExpectProxyAuthenticated(f, issuer2Bundle, payload)
	})

	It("rejects a token carrying none of the issuer's audiences", func() {
		payload := tokenPayloadWithAudiences(issuer2URL, []string{"not-configured-audience"})
		sharedtests.ExpectProxyUnauthorized(f, issuer2Bundle, payload)
	})

	It("does not let one issuer's extra audience satisfy another issuer", func() {
		payload := tokenPayloadWithAudiences(f.IssuerURL(), []string{issuer2ExtraAudience})
		sharedtests.ExpectProxyUnauthorized(f, f.IssuerKeyBundle(), payload)
	})
})

// tokenPayloadWithAudiences returns a payload for the suite's fixed identity
// whose aud claim is exactly audiences, so a spec can pick which configured
// audiences a token carries.
func tokenPayloadWithAudiences(issuerURL *url.URL, audiences []string) []byte {
	payload, err := json.Marshal(map[string]interface{}{
		"iss":    issuerURL.String(),
		"aud":    audiences,
		"email":  "user@example.com",
		"groups": []string{"group-1", "group-2"},
		"exp":    time.Now().Add(time.Minute).Unix(),
	})
	Expect(err).NotTo(HaveOccurred())
	return payload
}

func authConfig(jwts ...apiserverv1.JWTAuthenticator) apiserverv1.AuthenticationConfiguration {
	return apiserverv1.AuthenticationConfiguration{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "apiserver.config.k8s.io/v1",
			Kind:       "AuthenticationConfiguration",
		},
		JWT: jwts,
	}
}

// jwtAuthenticator builds one jwt entry. More than one audience requires
// audienceMatchPolicy MatchAny, the only policy the API defines; it is set
// whenever several audiences are given, so the entry always validates.
func jwtAuthenticator(issuerURL string, caBundle []byte, audiences ...string) apiserverv1.JWTAuthenticator {
	emptyPrefix := ""
	issuer := apiserverv1.Issuer{
		URL:                  issuerURL,
		Audiences:            audiences,
		CertificateAuthority: string(caBundle),
	}
	if len(audiences) > 1 {
		issuer.AudienceMatchPolicy = apiserverv1.AudienceMatchPolicyMatchAny
	}
	return apiserverv1.JWTAuthenticator{
		Issuer: issuer,
		ClaimMappings: apiserverv1.ClaimMappings{
			Username: apiserverv1.PrefixedClaimOrExpression{Claim: "email", Prefix: &emptyPrefix},
			Groups:   apiserverv1.PrefixedClaimOrExpression{Claim: "groups", Prefix: &emptyPrefix},
		},
	}
}

func configMapVolume(name string) corev1.Volume {
	return corev1.Volume{
		Name: name,
		VolumeSource: corev1.VolumeSource{
			ConfigMap: &corev1.ConfigMapVolumeSource{
				LocalObjectReference: corev1.LocalObjectReference{Name: name},
			},
		},
	}
}
