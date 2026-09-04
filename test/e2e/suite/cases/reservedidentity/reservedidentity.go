// Copyright Jetstack Ltd. See LICENSE for details.
package reservedidentity

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	rbacv1 "k8s.io/api/rbac/v1"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"github.com/rafpe/kube-oidc-proxy/test/e2e/framework"
	"github.com/rafpe/kube-oidc-proxy/test/e2e/suite/cases/sharedtests"
	"github.com/rafpe/kube-oidc-proxy/test/kind"
)

const (
	// defaultUsername is the username the suite's OIDC identity normally
	// carries, and the one the proxy's e2e RBAC binds impersonation rights to.
	defaultUsername = "user@example.com"

	// impersonationTarget is deliberately a user that defaultUsername has *no*
	// standing right to impersonate: the proxy's e2e RBAC grants that only for
	// ok-to-impersonate@nodomain.dev. The only authorization that can pass the
	// SubjectAccessReview for this target is the forged system:masters group in
	// the token, which is what makes the opt-out spec a real falsifier rather
	// than a request that would have succeeded anyway.
	impersonationTarget = "foo@example.com"

	// reservedGroup is cluster-admin by default in any kubeadm-built cluster,
	// kind included, through the cluster-admin ClusterRoleBinding.
	reservedGroup = "system:masters"

	// reservedUsername is the username-side escalation: the proxy is granted
	// impersonate on serviceaccounts with no resourceNames, so a username claim
	// of this shape is any service account in the cluster.
	reservedUsername = "system:serviceaccount:kube-system:default"

	// forbiddenBody is the tail of the body the proxy writes when it refuses a
	// reserved identity. Matched as a substring, and without the quoted
	// "system:" fragment of the full message, so the assertion does not depend
	// on how quotes survive the client's error decoding. It is distinct from
	// every other 403 the proxy can produce, in particular from the
	// "is not allowed to impersonate" denial a SubjectAccessReview yields —
	// which is the 403 this request would get if the guard ran after the SAR
	// instead of before it.
	forbiddenBody = "are not accepted from an authentication token"

	// sarRequestPath identifies a SubjectAccessReview in the proxy's own logs.
	// The suite deploys the proxy with --v=10, at which client-go logs every
	// request it makes to the API server (transport.DebugWrappers installs its
	// debugging round tripper from V(6) up), so a submitted SAR appears as the
	// path of the logged request. The API server the suite runs against is a
	// kind cluster with no audit log enabled, so the proxy's own logs are where
	// "no SubjectAccessReview was submitted" is observable end to end; the
	// paired opt-out spec asserts the same string *does* appear, so this
	// mechanism cannot silently stop working and leave the assertion below
	// passing for the wrong reason.
	sarRequestPath = "subjectaccessreviews"
)

var _ = framework.CasesDescribe("Reserved identity", Label("shard-c"), func() {
	// The guard is on by default. None of these specs gets past it, so none of
	// them leaves residue another depends on and they share a single deploy.
	Describe("refused", Ordered, ContinueOnFailure, func() {
		f := framework.NewOrderedDefaultFramework("reserved-identity")

		BeforeAll(func() {
			By("Granting pod list to the impersonation target and to the token's own user")
			grantPodList(f, impersonationTarget)
			grantPodList(f, defaultUsername)
		})

		It("should refuse a token whose groups claim contains system:masters, without reaching the SubjectAccessReview", func() {
			By("Listing pods with a system:masters group claim and an Impersonate-User header")
			code, body := listPods(f, signedTokenFor(f, defaultUsername, []string{reservedGroup}), impersonationTarget)

			Expect(code).To(Equal(http.StatusForbidden), body)
			Expect(body).To(ContainSubstring(forbiddenBody))

			By("Checking the refusal was recorded as an anomaly")
			// A token minting a reserved identity is an exploit attempt, not an
			// ordinary denial, so it is recorded as one alongside the access
			// record. The record is written on the same code path as the
			// refusal, which is what makes waiting for it the right way to
			// know the proxy's whole output for this request is readable:
			// any SubjectAccessReview would have been submitted before the
			// response the client has already received.
			var raw string
			Eventually(func() []map[string]any {
				var recs []map[string]any
				recs, raw = proxyLogs(f)
				return sharedtests.ByEvent(recs, "request.anomaly.detected")
			}, time.Second*15, time.Second).ShouldNot(BeEmpty(),
				"the proxy refused a reserved identity without recording request.anomaly.detected")

			By("Checking no SubjectAccessReview was submitted for the request")
			Expect(raw).NotTo(ContainSubstring(sarRequestPath),
				"the proxy submitted a SubjectAccessReview for an identity it refused; the guard must run before the SAR, "+
					"which builds its review from the requester's own (forged) groups")
		})

		It("should refuse a token whose username claim has the reserved system: prefix", func() {
			By("Listing pods as a service account username, with no impersonation")
			code, body := listPods(f, signedTokenFor(f, reservedUsername, []string{"group-1"}), "")

			Expect(code).To(Equal(http.StatusForbidden), body)
			Expect(body).To(ContainSubstring(forbiddenBody))
		})

		It("should accept a token whose groups claim contains system:authenticated", func() {
			// The one exception on the group side: the proxy appends
			// system:authenticated to every request itself, so an issuer that
			// also emits it must not be refused. The username rule has no such
			// exception, which the spec above covers.
			By("Listing pods with a system:authenticated group claim")
			code, body := listPods(f, signedTokenFor(f, defaultUsername, []string{"system:authenticated", "group-1"}), "")

			Expect(code).To(Equal(http.StatusOK), body)
		})
	})

	// The falsifier. Same token, same request, same cluster state as the first
	// spec above; the only difference is that the group is allowlisted. The request has to
	// reach the API server and succeed here, which is what makes the 403 and
	// the absent SubjectAccessReview above attributable to the guard rather
	// than to anything else about the request.
	Describe("allowed by --allow-reserved-groups", func() {
		f := framework.NewDefaultFramework("reserved-identity-allowlist")

		It("should let a system:masters group claim authorize an impersonation it otherwise could not", func() {
			By("Redeploying the proxy with the group allowlisted")
			f.DeployProxyWith(nil, "--allow-reserved-groups="+reservedGroup)

			By("Granting pod list to the impersonation target")
			grantPodList(f, impersonationTarget)

			By("Listing pods with a system:masters group claim and an Impersonate-User header")
			code, body := listPods(f, signedTokenFor(f, defaultUsername, []string{reservedGroup}), impersonationTarget)

			// 200 only because the SubjectAccessReview authorizing the
			// impersonation was built with the token's forged system:masters
			// group. This is the escalation the guard exists to prevent.
			Expect(code).To(Equal(http.StatusOK), body)

			By("Checking the SubjectAccessReview did reach the API server")
			Eventually(func() string {
				_, raw := proxyLogs(f)
				return raw
			}, time.Second*15, time.Second).
				Should(ContainSubstring(sarRequestPath),
					"no SubjectAccessReview was logged even with the group allowlisted, so the zero-SAR assertion "+
						"in the refused specs cannot be trusted to fail")
		})
	})
})

// grantPodList gives username permission to list pods in the test namespace.
func grantPodList(f *framework.Framework, username string) {
	role, err := f.Helper().KubeClient.RbacV1().Roles(f.Namespace.Name).Create(context.TODO(), &rbacv1.Role{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: "reserved-identity-pods-",
		},
		Rules: []rbacv1.PolicyRule{
			{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"get", "list"}},
		},
	}, metav1.CreateOptions{})
	Expect(err).NotTo(HaveOccurred())

	_, err = f.Helper().KubeClient.RbacV1().RoleBindings(f.Namespace.Name).Create(context.TODO(),
		&rbacv1.RoleBinding{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: "reserved-identity-pods-",
			},
			Subjects: []rbacv1.Subject{{Name: username, Kind: "User"}},
			RoleRef:  rbacv1.RoleRef{Name: role.Name, Kind: "Role"},
		}, metav1.CreateOptions{})
	Expect(err).NotTo(HaveOccurred())
}

// signedTokenFor mints a token for the given identity, signed by the suite's
// mock issuer.
func signedTokenFor(f *framework.Framework, username string, groups []string) string {
	payload, err := f.Helper().NewTokenPayloadForIdentity(f.IssuerURL(), f.ClientID(),
		username, groups, time.Now().Add(time.Minute*10))
	Expect(err).NotTo(HaveOccurred())

	signedToken, err := f.Helper().SignToken(f.IssuerKeyBundle(), payload)
	Expect(err).NotTo(HaveOccurred())

	return signedToken
}

// listPods lists pods in the test namespace through the proxy with the given
// token, impersonating impersonateUser when it is non-empty. It returns the
// response status code and, for a failure, the message the proxy wrote.
func listPods(f *framework.Framework, signedToken, impersonateUser string) (int, string) {
	config := f.NewProxyRestConfig()
	config.BearerToken = signedToken
	if impersonateUser != "" {
		config.Impersonate = rest.ImpersonationConfig{UserName: impersonateUser}
	}

	client, err := kubernetes.NewForConfig(config)
	Expect(err).NotTo(HaveOccurred())

	_, err = client.CoreV1().Pods(f.Namespace.Name).List(context.TODO(), metav1.ListOptions{})
	if err == nil {
		return http.StatusOK, ""
	}

	var statusErr *k8sErrors.StatusError
	if !errors.As(err, &statusErr) {
		Expect(fmt.Errorf("expected a status error from the proxy, got=%s", err)).NotTo(HaveOccurred())
	}

	// A body the proxy wrote itself is not a Status object, so the client
	// carries it as an unexpected-response cause rather than in the message.
	body := statusErr.Error()
	if details := statusErr.Status().Details; details != nil && len(details.Causes) > 0 {
		body = details.Causes[0].Message
	}

	return int(statusErr.ErrStatus.Code), body
}

// proxyLogs returns the decoded records the proxy currently deployed in the
// test namespace has written, and the raw log text they were decoded from. The
// SubjectAccessReview assertions match the raw text: the path appears inside a
// bridged client-go message, so it is a substring of the JSON line rather than
// a field of its own.
func proxyLogs(f *framework.Framework) ([]map[string]any, string) {
	recs, raw, err := f.Helper().ProxyLogRecords(f.Namespace.Name, "app="+kind.ProxyImageName)
	Expect(err).NotTo(HaveOccurred())

	return recs, raw
}
