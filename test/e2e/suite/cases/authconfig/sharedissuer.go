// Copyright Jetstack Ltd. See LICENSE for details.

//go:build e2e

package authconfig

import (
	"context"
	"net/http"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	apiserverv1 "k8s.io/apiserver/pkg/apis/apiserver/v1"
	"sigs.k8s.io/yaml"

	"github.com/rafpe/kube-oidc-proxy/internal/devkit/idtoken"
	"github.com/rafpe/kube-oidc-proxy/pkg/authn/v1alpha1"
	"github.com/rafpe/kube-oidc-proxy/test/e2e/framework"
	"github.com/rafpe/kube-oidc-proxy/test/e2e/suite/cases/sharedtests"
)

const (
	sharedConfigVolume = "shared-issuer-config"
	audienceInternal   = "aud-internal"
	audienceVendor     = "aud-vendor"
)

// Two trust groups on one issuer URL, as ADR-0001 describes. Each group has
// its own audience and username prefix. Only the internal group has RBAC
// access to pods.
var _ = framework.CasesDescribe("AuthenticationConfiguration of the proxy kind with a shared issuer URL", Ordered, ContinueOnFailure, Label("shard-a"), func() {
	f := framework.NewOrderedDefaultFramework("sharedissuer")

	f.BeforeProxyDeploy = func(ctx context.Context) {
		By("Creating the proxy AuthenticationConfiguration ConfigMap")
		issuerURL := f.IssuerURL().String()
		caBundle := f.IssuerKeyBundle().CertBytes
		cfgYAML, err := yaml.Marshal(v1alpha1.AuthenticationConfiguration{
			TypeMeta: metav1.TypeMeta{APIVersion: v1alpha1.APIVersion, Kind: v1alpha1.Kind},
			Issuers: []v1alpha1.Issuer{
				{Name: "internal", JWT: prefixedJWTAuthenticator(issuerURL, caBundle, audienceInternal, "internal:")},
				{Name: "vendor", JWT: prefixedJWTAuthenticator(issuerURL, caBundle, audienceVendor, "vendor:")},
			},
		})
		Expect(err).NotTo(HaveOccurred())

		_, err = f.Helper().KubeClient.CoreV1().ConfigMaps(f.Namespace.Name).Create(ctx,
			&corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{Name: sharedConfigVolume},
				Data:       map[string]string{authConfigKey: string(cfgYAML)},
			},
			metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())

		By("Letting only the internal user list pods")
		_, err = f.Helper().KubeClient.RbacV1().Roles(f.Namespace.Name).Create(ctx,
			&rbacv1.Role{
				ObjectMeta: metav1.ObjectMeta{Name: "shared-issuer-pods"},
				Rules:      []rbacv1.PolicyRule{{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"list"}}},
			},
			metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())
		_, err = f.Helper().KubeClient.RbacV1().RoleBindings(f.Namespace.Name).Create(ctx,
			&rbacv1.RoleBinding{
				ObjectMeta: metav1.ObjectMeta{Name: "shared-issuer-pods"},
				Subjects:   []rbacv1.Subject{{Kind: rbacv1.UserKind, Name: "internal:" + idtoken.DefaultUsername}},
				RoleRef:    rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "Role", Name: "shared-issuer-pods"},
			},
			metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())

		f.ExtraProxyVolumes = []corev1.Volume{configMapVolume(sharedConfigVolume)}
		f.ExtraProxyArgs = []string{"--authentication-config=/" + sharedConfigVolume + "/" + authConfigKey}
	}

	It("routes a token with the internal audience to the internal issuer", func() {
		payload := tokenPayloadWithAudiences(f.IssuerURL(), []string{audienceInternal})
		sharedtests.ExpectProxyStatus(f, f.IssuerKeyBundle(), payload, http.StatusOK)
	})

	It("routes a token with the vendor audience to the vendor issuer, which has no RBAC access", func() {
		payload := tokenPayloadWithAudiences(f.IssuerURL(), []string{audienceVendor})
		sharedtests.ExpectProxyStatus(f, f.IssuerKeyBundle(), payload, http.StatusForbidden)
	})

	It("rejects a token whose audience selects no issuer", func() {
		payload := tokenPayloadWithAudiences(f.IssuerURL(), []string{"not-configured-audience"})
		sharedtests.ExpectProxyUnauthorized(f, f.IssuerKeyBundle(), payload)
	})

	It("rejects a token whose audiences select two issuers", func() {
		payload := tokenPayloadWithAudiences(f.IssuerURL(), []string{audienceInternal, audienceVendor})
		sharedtests.ExpectProxyUnauthorized(f, f.IssuerKeyBundle(), payload)
	})
})

// prefixedJWTAuthenticator builds one jwt entry with one audience and the
// given username prefix.
func prefixedJWTAuthenticator(issuerURL string, caBundle []byte, audience, usernamePrefix string) apiserverv1.JWTAuthenticator {
	jwt := jwtAuthenticator(issuerURL, caBundle, audience)
	jwt.ClaimMappings.Username.Prefix = &usernamePrefix
	return jwt
}
