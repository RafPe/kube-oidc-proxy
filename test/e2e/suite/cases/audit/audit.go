// Copyright Jetstack Ltd. See LICENSE for details.
package passthrough

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	auditv1 "k8s.io/apiserver/pkg/apis/audit/v1"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/remotecommand"

	"github.com/rafpe/kube-oidc-proxy/test/e2e/framework"
	"github.com/rafpe/kube-oidc-proxy/test/util"
)

const (
	// The proxy image is distroless and runs as nonroot, so the audit log has
	// to be written to a writable emptyDir rather than the root filesystem, and
	// read back through a sidecar since the proxy image has no shell or cat.
	auditLogDir     = "/var/log/kube-oidc-proxy"
	auditLogPath    = auditLogDir + "/audit.log"
	auditLogVolume  = "audit-log"
	auditReaderName = "audit-reader"

	// webhookAuditPath is where the audit webhook sink writes events inside its
	// own pod.
	webhookAuditPath = "/audit-log"
)

var _ = framework.CasesDescribe("Audit", Label("shard-b"), func() {
	f := framework.NewDefaultFramework("audit")

	It("should be able to write audit logs to file", func() {
		deployProxyWithAuditLogFile(f)

		testAuditLogs(f, "app=kube-oidc-proxy-e2e", auditReaderName, auditLogPath)
	})

	// A streaming request has to be recorded when the stream starts, not only
	// when it ends: the proxy treats kube-apiserver's long running verbs and
	// subresources as long running, so an exec is audited as soon as the
	// connection is upgraded. Without that, an hour long exec leaves nothing in
	// the audit log for that hour, and nothing at all if the proxy dies first.
	It("should write a ResponseStarted audit event when a long running request starts", func() {
		deployProxyWithAuditLogFile(f)

		// The exec target is the audit reader sidecar of the proxy pod itself.
		// It is a shell bearing image that the suite builds for the host
		// architecture and it is already running, so this needs no further pod
		// and no image pulled from a registry. The exec still leaves the proxy
		// as a streaming request to the apiserver, which is what is under test.
		pod := proxyPod(f)

		By("Creating Role")
		_, err := f.Helper().KubeClient.RbacV1().Roles(f.Namespace.Name).Create(context.TODO(), &rbacv1.Role{
			ObjectMeta: metav1.ObjectMeta{
				Name: "e2e-test-audit-exec",
			},
			Rules: []rbacv1.PolicyRule{
				{
					APIGroups: []string{""},
					Resources: []string{
						"pods", "pods/exec",
					},
					Verbs: []string{
						"get", "list", "create",
					},
				},
			},
		}, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())

		By("Creating RoleBinding")
		_, err = f.Helper().KubeClient.RbacV1().RoleBindings(f.Namespace.Name).Create(context.TODO(),
			&rbacv1.RoleBinding{
				ObjectMeta: metav1.ObjectMeta{
					Name: "e2e-test-audit-exec",
				},
				Subjects: []rbacv1.Subject{
					{
						Name: "user@example.com",
						Kind: "User",
					},
				},
				RoleRef: rbacv1.RoleRef{
					Name: "e2e-test-audit-exec",
					Kind: "Role",
				},
			}, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())

		By("Running exec into pod through the proxy")
		restConfig := newExecRestConfig(f)

		restClient, err := rest.RESTClientFor(restConfig)
		Expect(err).NotTo(HaveOccurred())

		req := restClient.Post().
			Resource("pods").
			Name(pod.Name).
			Namespace(pod.Namespace).
			SubResource("exec").
			VersionedParams(&corev1.PodExecOptions{
				Container: auditReaderName,
				Command: []string{
					"sh", "-c", "echo hello world",
				},
				Stdout: true,
				Stderr: true,
			}, scheme.ParameterCodec)

		executor, err := remotecommand.NewSPDYExecutor(restConfig, "POST", req.URL())
		Expect(err).NotTo(HaveOccurred())

		execOut, execErr := new(bytes.Buffer), new(bytes.Buffer)
		err = executor.StreamWithContext(context.TODO(), remotecommand.StreamOptions{
			Stdout: execOut,
			Stderr: execErr,
		})
		Expect(err).NotTo(HaveOccurred(), "exec through the proxy failed, stderr=%s", execErr.String())

		// The stream has to have carried real traffic, otherwise a
		// ResponseStarted event would prove nothing about streaming requests.
		Expect(execOut.String()).To(ContainSubstring("hello world"),
			"exec stream carried no output")

		By("Waiting for audit logs to be written")
		// 5 seconds here is longer than the proxy flush interval.
		time.Sleep(time.Second * 5)

		By("Copying audit log from proxy locally")
		logs := readAuditLog(f, "app=kube-oidc-proxy-e2e", auditReaderName, auditLogPath)

		By("Testing for the expected audit stages of the exec request")
		// The exec request URI carries the command as a query string, so match
		// on the path prefix.
		execURI := fmt.Sprintf("/api/v1/namespaces/%s/pods/%s/exec", pod.Namespace, pod.Name)

		var stages []auditv1.Stage
		scanner := bufio.NewScanner(bytes.NewReader(logs))
		for scanner.Scan() {
			var auditEvent auditv1.Event
			err = json.Unmarshal(scanner.Bytes(), &auditEvent)
			Expect(err).NotTo(HaveOccurred())

			if !strings.HasPrefix(auditEvent.RequestURI, execURI) {
				continue
			}

			Expect(auditEvent.User.Username).To(Equal("user@example.com"))

			// The classification the long running check reads. A POST to a
			// subresource is the "create" verb, and the subresource is what
			// makes the request long running, so an event recording neither
			// means the request was never resolved as a resource request.
			Expect(auditEvent.Verb).To(Equal("create"))
			Expect(auditEvent.ObjectRef).NotTo(BeNil(), "audit event carries no objectRef, so the exec was not audited as a resource request")
			Expect(auditEvent.ObjectRef.Resource).To(Equal("pods"))
			Expect(auditEvent.ObjectRef.Subresource).To(Equal("exec"))

			stages = append(stages, auditEvent.Stage)
		}
		Expect(scanner.Err()).NotTo(HaveOccurred())

		// The event that only a long running request produces. A request that
		// is not treated as long running is recorded once, at completion, with
		// no ResponseStarted event at all.
		Expect(stages).To(ContainElement(auditv1.StageResponseStarted),
			"exec through the proxy emitted no ResponseStarted audit event, so it was not audited as a long running request\naudit log:\n%s", logs)

		Expect(stages).To(Equal([]auditv1.Stage{
			auditv1.StageRequestReceived,
			auditv1.StageResponseStarted,
			auditv1.StageResponseComplete,
		}), "unexpected audit stages for %s\naudit log:\n%s", execURI, logs)
	})

	// Watch is the one long running verb the generic apiserver default already
	// covered, so this spec is not about the long-running set. It covers the
	// classification underneath: a watch of a core group resource is only
	// recognised as a watch — rather than a plain GET — once the audit config
	// names the legacy API prefix. Until then no core group watch was ever
	// audited as long running, whatever the set contained.
	It("should write a ResponseStarted audit event when a watch starts", func() {
		deployProxyWithAuditLogFile(f)

		By("Creating Role")
		_, err := f.Helper().KubeClient.RbacV1().Roles(f.Namespace.Name).Create(context.TODO(), &rbacv1.Role{
			ObjectMeta: metav1.ObjectMeta{
				Name: "e2e-test-audit-watch",
			},
			Rules: []rbacv1.PolicyRule{
				{
					APIGroups: []string{""},
					Resources: []string{"pods"},
					Verbs:     []string{"get", "list", "watch"},
				},
			},
		}, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())

		By("Creating RoleBinding")
		_, err = f.Helper().KubeClient.RbacV1().RoleBindings(f.Namespace.Name).Create(context.TODO(),
			&rbacv1.RoleBinding{
				ObjectMeta: metav1.ObjectMeta{
					Name: "e2e-test-audit-watch",
				},
				Subjects: []rbacv1.Subject{
					{
						Name: "user@example.com",
						Kind: "User",
					},
				},
				RoleRef: rbacv1.RoleRef{
					Name: "e2e-test-audit-watch",
					Kind: "Role",
				},
			}, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())

		By("Watching pods through the proxy")
		token := util.NewTokenPayload(f.IssuerURL(), f.ClientID(), time.Now().Add(time.Minute*10))
		signedToken, err := util.SignToken(f.IssuerKeyBundle(), token)
		Expect(err).NotTo(HaveOccurred())

		proxyConfig := f.NewProxyRestConfig()
		requester := f.Helper().NewRequester(proxyConfig.Transport, signedToken)

		// The watch is held open by the apiserver until timeoutSeconds elapses,
		// so the request really does stream, and the read of the body below
		// only returns once the stream has ended.
		watchPath := fmt.Sprintf("/api/v1/namespaces/%s/pods", f.Namespace.Name)
		watchURI := watchPath + "?timeoutSeconds=2&watch=true"

		_, resp, err := requester.Get(proxyConfig.Host + watchURI)
		Expect(err).NotTo(HaveOccurred())
		Expect(resp.StatusCode).To(Equal(http.StatusOK),
			"watch through the proxy was not served, so no stream was ever started")

		By("Waiting for audit logs to be written")
		// 5 seconds here is longer than the proxy flush interval.
		time.Sleep(time.Second * 5)

		By("Copying audit log from proxy locally")
		logs := readAuditLog(f, "app=kube-oidc-proxy-e2e", auditReaderName, auditLogPath)

		By("Testing for the expected audit stages of the watch request")
		var stages []auditv1.Stage
		scanner := bufio.NewScanner(bytes.NewReader(logs))
		for scanner.Scan() {
			var auditEvent auditv1.Event
			err = json.Unmarshal(scanner.Bytes(), &auditEvent)
			Expect(err).NotTo(HaveOccurred())

			if auditEvent.RequestURI != watchURI {
				continue
			}

			Expect(auditEvent.User.Username).To(Equal("user@example.com"))

			// A GET carrying watch=true is the "watch" verb, not "get" — which
			// is the classification the long running check reads.
			Expect(auditEvent.Verb).To(Equal("watch"))
			Expect(auditEvent.ObjectRef).NotTo(BeNil(), "audit event carries no objectRef, so the watch was not audited as a resource request")
			Expect(auditEvent.ObjectRef.Resource).To(Equal("pods"))
			Expect(auditEvent.ObjectRef.Namespace).To(Equal(f.Namespace.Name))

			stages = append(stages, auditEvent.Stage)
		}
		Expect(scanner.Err()).NotTo(HaveOccurred())

		Expect(stages).To(ContainElement(auditv1.StageResponseStarted),
			"watch through the proxy emitted no ResponseStarted audit event, so it was not audited as a long running request\naudit log:\n%s", logs)

		Expect(stages).To(Equal([]auditv1.Stage{
			auditv1.StageRequestReceived,
			auditv1.StageResponseStarted,
			auditv1.StageResponseComplete,
		}), "unexpected audit stages for %s\naudit log:\n%s", watchURI, logs)
	})

	It("should be able to write audit logs to webhook", func() {
		By("Creating policy file ConfigMap")
		cmPolicy, err := f.Helper().KubeClient.CoreV1().ConfigMaps(f.Namespace.Name).Create(context.TODO(), &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: "kube-oidc-proxy-policy-",
			},
			Data: map[string]string{
				"audit.yaml": `apiVersion: audit.k8s.io/v1
kind: Policy
rules:
- level: RequestResponse`,
			},
		}, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())

		extraWebhookVol, webhookURL, err := f.Helper().DeployAuditWebhook(f.Namespace.Name, webhookAuditPath)
		Expect(err).NotTo(HaveOccurred())

		cmWebhook, err := f.Helper().KubeClient.CoreV1().ConfigMaps(f.Namespace.Name).Create(context.TODO(), &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: "kube-oidc-proxy-webhook-config-",
			},
			Data: map[string]string{
				"kubeconfig.yaml": `apiVersion: v1
kind: Config
clusters:
- cluster:
    server: ` + webhookURL.String() + `
    certificate-authority: /audit-webhook-ca/ca.pem
  name: logstash
contexts:
- context:
    cluster: logstash
    user: ""
  name: default-context
current-context: default-context
preferences: {}
users: []`,
			},
		}, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())

		vols := []corev1.Volume{
			{
				Name: "audit",
				VolumeSource: corev1.VolumeSource{
					ConfigMap: &corev1.ConfigMapVolumeSource{
						LocalObjectReference: corev1.LocalObjectReference{
							Name: cmPolicy.Name,
						},
					},
				},
			},
			{
				Name: "audit-webhook",
				VolumeSource: corev1.VolumeSource{
					ConfigMap: &corev1.ConfigMapVolumeSource{
						LocalObjectReference: corev1.LocalObjectReference{
							Name: cmWebhook.Name,
						},
					},
				},
			},
			extraWebhookVol,
		}

		By("Deploying proxy with audit policy enabled")
		f.DeployProxyWith(vols, "--audit-webhook-config-file=/audit-webhook/kubeconfig.yaml",
			"--audit-policy-file=/audit/audit.yaml", "--audit-webhook-initial-backoff=1s", "--audit-webhook-batch-max-wait=1s")

		testAuditLogs(f, "app=audit-webhook-e2e", "", webhookAuditPath)
	})
})
