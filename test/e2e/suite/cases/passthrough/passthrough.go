// Copyright Jetstack Ltd. See LICENSE for details.

//go:build e2e

package passthrough

import (
	"errors"
	"fmt"
	"net/http"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	rbacv1 "k8s.io/api/rbac/v1"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/rafpe/kube-oidc-proxy/test/e2e/framework"
)

// The specs share the initial issuer and proxy deploy; the second redeploys the
// proxy itself to enable passthrough. The per-spec Role and RoleBinding below
// are still created and deleted around every spec, so the shared namespace
// looks the same to each of them.
var _ = framework.CasesDescribe("Passthrough", Ordered, ContinueOnFailure, Label("shard-c"), func() {
	f := framework.NewOrderedDefaultFramework("passthrough")

	var saToken string

	JustBeforeEach(func(ctx SpecContext) {
		By("Creating List Pods Role")
		_, err := f.Helper().KubeClient.RbacV1().Roles(f.Namespace.Name).Create(ctx,
			&rbacv1.Role{
				ObjectMeta: metav1.ObjectMeta{
					Name: "e2e-impersonation-pods-list",
				},
				Rules: []rbacv1.PolicyRule{
					{
						APIGroups: []string{""},
						Resources: []string{"pods"},
						Verbs:     []string{"get", "list"},
					},
				},
			}, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())

		// Create bindings for both the OIDC user and default ServiceAccount
		By("Creating List Pods RoleBinding")
		_, err = f.Helper().KubeClient.RbacV1().RoleBindings(f.Namespace.Name).Create(ctx,
			&rbacv1.RoleBinding{
				ObjectMeta: metav1.ObjectMeta{
					Name: "e2e-impersonation-pods-list",
				},
				Subjects: []rbacv1.Subject{
					{Name: "user@example.com", Kind: "User"},
					{Name: "default", Kind: "ServiceAccount"},
				},
				RoleRef: rbacv1.RoleRef{
					Name: "e2e-impersonation-pods-list", Kind: "Role"},
			}, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())

		By("Getting the token for the default ServiceAccount")
		saToken, err = f.Helper().GetServiceAccountToken(ctx, f.Namespace.Name, "default")
		Expect(err).NotTo(HaveOccurred())
	})

	JustAfterEach(func(ctx SpecContext) {
		By("Deleting List Pods Role")
		err := f.Helper().KubeClient.RbacV1().Roles(f.Namespace.Name).Delete(ctx,
			"e2e-impersonation-pods-list", metav1.DeleteOptions{})
		Expect(err).NotTo(HaveOccurred())

		By("Creating List Pods RoleBinding")
		err = f.Helper().KubeClient.RbacV1().RoleBindings(f.Namespace.Name).Delete(ctx,
			"e2e-impersonation-pods-list", metav1.DeleteOptions{})
		Expect(err).NotTo(HaveOccurred())
	})

	It("error when a valid OIDC token is used but return correct when passthrough is disabled", func(ctx SpecContext) {
		By("A valid OIDC token should respond without error")
		proxyClient := f.NewProxyClient()
		_, err := proxyClient.CoreV1().Pods(f.Namespace.Name).List(ctx, metav1.ListOptions{})
		Expect(err).NotTo(HaveOccurred())

		By("Using a ServiceAccount token should error by the proxy")

		// Create requester using the ServiceAccount token
		config := f.NewProxyRestConfig()
		config.BearerToken = saToken

		client, err := kubernetes.NewForConfig(config)
		Expect(err).NotTo(HaveOccurred())

		_, err = client.CoreV1().Pods(f.Namespace.Name).List(ctx, metav1.ListOptions{})
		var statusErr *k8sErrors.StatusError
		if !errors.As(err, &statusErr) {
			Expect(fmt.Errorf("expected a status error from the proxy, got=%v", err)).NotTo(HaveOccurred())
		}

		expRespBody := "Unauthorized"
		resp := statusErr.Error()
		if details := statusErr.Status().Details; details != nil && len(details.Causes) > 0 {
			resp = details.Causes[0].Message
		}

		// Check body and status code the token was rejected
		if int(statusErr.Status().Code) != http.StatusUnauthorized ||
			resp != expRespBody {
			Expect(fmt.Errorf("expected status code %d with body %q, got= %d %q",
				http.StatusUnauthorized, expRespBody, int(statusErr.Status().Code), resp)).NotTo(HaveOccurred())
		}
	})

	It("should not error on a valid OIDC token nor a valid ServiceAccount token with passthrough enabled", func(ctx SpecContext) {
		By("Enabling passthrough with Audience of the API Server")
		f.DeployProxyWith(ctx, nil, "--token-passthrough")

		By("A valid OIDC token should respond without error")
		proxyClient := f.NewProxyClient()
		_, err := proxyClient.CoreV1().Pods(f.Namespace.Name).List(ctx, metav1.ListOptions{})
		Expect(err).NotTo(HaveOccurred())

		By("Using a ServiceAccount token should not error")

		// Create kube client using ServiceAccount token
		proxyConfig := f.NewProxyRestConfig()
		proxyConfig.BearerToken = saToken
		kubeProxyClient, err := kubernetes.NewForConfig(proxyConfig)
		Expect(err).NotTo(HaveOccurred())

		_, err = kubeProxyClient.CoreV1().Pods(f.Namespace.Name).List(ctx, metav1.ListOptions{})
		Expect(err).NotTo(HaveOccurred())
	})
})
