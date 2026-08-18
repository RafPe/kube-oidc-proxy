// Copyright Jetstack Ltd. See LICENSE for details.
package passthrough

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"reflect"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	authnv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	auditv1 "k8s.io/apiserver/pkg/apis/audit/v1"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/remotecommand"

	"github.com/rafpe/kube-oidc-proxy/test/e2e/framework"
	"github.com/rafpe/kube-oidc-proxy/test/e2e/framework/helper"
	"github.com/rafpe/kube-oidc-proxy/test/kind"
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

// deployProxyWithAuditLogFile redeploys the proxy auditing at level
// RequestResponse to a file, which is read back with readAuditLog.
func deployProxyWithAuditLogFile(f *framework.Framework) {
	By("Creating policy file ConfigMap")
	cm, err := f.Helper().KubeClient.CoreV1().ConfigMaps(f.Namespace.Name).Create(context.TODO(), &corev1.ConfigMap{
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

	vols := []corev1.Volume{
		{
			Name: "audit",
			VolumeSource: corev1.VolumeSource{
				ConfigMap: &corev1.ConfigMapVolumeSource{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: cm.Name,
					},
				},
			},
		},
	}

	// The audit log lives in an emptyDir shared with a reader sidecar. The
	// sidecar uses the audit webhook image because it is alpine based (so it
	// has cat), runs as root (so it can read the log file written by the
	// nonroot proxy) and is already loaded into the kind nodes.
	extras := &helper.ProxyExtras{
		Volumes: []corev1.Volume{
			{
				Name: auditLogVolume,
				VolumeSource: corev1.VolumeSource{
					EmptyDir: &corev1.EmptyDirVolumeSource{},
				},
			},
		},
		VolumeMounts: []corev1.VolumeMount{
			{
				MountPath: auditLogDir,
				Name:      auditLogVolume,
			},
		},
		Containers: []corev1.Container{
			{
				Name:            auditReaderName,
				Image:           kind.AuditWebhookImageName,
				ImagePullPolicy: corev1.PullNever,
				Command:         []string{"sleep", "86400"},
				VolumeMounts: []corev1.VolumeMount{
					{
						MountPath: auditLogDir,
						Name:      auditLogVolume,
						ReadOnly:  true,
					},
				},
			},
		},
	}

	By("Deploying proxy with audit policy enabled")
	f.DeployProxyWithExtras(vols, extras,
		"--audit-log-path="+auditLogPath, "--audit-policy-file=/audit/audit.yaml")
}

// newExecRestConfig returns a rest config for streaming requests through the
// proxy. SPDY builds its own transport from TLSClientConfig, so unlike
// Framework.NewProxyRestConfig this cannot hand over a prebuilt transport.
func newExecRestConfig(f *framework.Framework) *rest.Config {
	payload := f.Helper().NewTokenPayload(f.IssuerURL(), f.ClientID(), time.Now().Add(time.Minute*10))
	signedToken, err := f.Helper().SignToken(f.IssuerKeyBundle(), payload)
	Expect(err).NotTo(HaveOccurred())

	return &rest.Config{
		Host:        f.ProxyURL().String(),
		BearerToken: signedToken,
		TLSClientConfig: rest.TLSClientConfig{
			CAData: f.ProxyKeyBundle().CertBytes,
		},

		APIPath: "/api",
		ContentConfig: rest.ContentConfig{
			GroupVersion:         &corev1.SchemeGroupVersion,
			NegotiatedSerializer: scheme.Codecs,
		},
	}
}

// proxyPod returns the single running proxy pod.
func proxyPod(f *framework.Framework) *corev1.Pod {
	return singlePod(f, "app=kube-oidc-proxy-e2e")
}

// singlePod returns the only pod matching podLabelSelector, failing the spec
// if there is not exactly one.
func singlePod(f *framework.Framework, podLabelSelector string) *corev1.Pod {
	pods, err := f.Helper().KubeClient.CoreV1().Pods(f.Namespace.Name).List(context.TODO(), metav1.ListOptions{
		LabelSelector: podLabelSelector,
	})
	Expect(err).NotTo(HaveOccurred())
	if len(pods.Items) != 1 {
		Expect(fmt.Errorf("expected single pod matching %s running, got=%d", podLabelSelector, len(pods.Items))).NotTo(HaveOccurred())
	}

	return &pods.Items[0]
}

// readAuditLog returns the contents of the audit log at logPath in the pod
// matching podLabelSelector. If containerName is non-empty the log is read
// from that container, otherwise from the pod's default container.
func readAuditLog(f *framework.Framework, podLabelSelector, containerName, logPath string) []byte {
	pod := singlePod(f, podLabelSelector)

	execArgs := []string{"exec", pod.Name}
	if containerName != "" {
		execArgs = append(execArgs, "-c", containerName)
	}
	execArgs = append(execArgs, "--", "cat", logPath)

	var auditLogsBuffer bytes.Buffer
	err := f.Helper().Kubectl(f.Namespace.Name).RunWithStdout(&auditLogsBuffer, execArgs...)
	Expect(err).NotTo(HaveOccurred())

	return auditLogsBuffer.Bytes()
}

// testAuditLogs reads the audit log at logPath from the pod matching
// podLabelSelector. If containerName is non-empty the log is read from that
// container, otherwise from the pod's default container.
func testAuditLogs(f *framework.Framework, podLabelSelector, containerName, logPath string) {
	By("Making calls to proxy to ensure audit get created")
	token := f.Helper().NewTokenPayload(f.IssuerURL(), f.ClientID(), time.Now().Add(time.Second*5))
	signedToken, err := f.Helper().SignToken(f.IssuerKeyBundle(), token)
	Expect(err).NotTo(HaveOccurred())

	proxyConfig := f.NewProxyRestConfig()
	requester := f.Helper().NewRequester(proxyConfig.Transport, signedToken)

	target := fmt.Sprintf("%s/api/v1/namespaces/kube-system/pods", proxyConfig.Host)

	// Make request that should succeed
	_, _, err = requester.Get(target)
	Expect(err).NotTo(HaveOccurred())

	// Make request that should be unauthenticated
	requester = f.Helper().NewRequester(proxyConfig.Transport, "foo")
	_, resp, err := requester.Get(target)
	Expect(err).NotTo(HaveOccurred())

	if resp.StatusCode != http.StatusUnauthorized {
		Expect(fmt.Errorf("expected to get unauthorized, got=%d", resp.StatusCode)).NotTo(HaveOccurred())
	}

	By("Waiting for audit logs to be written")
	// 5 seconds here is longer than the proxy flush interval.
	time.Sleep(time.Second * 5)

	By("Copying audit log from proxy locally")
	logs := readAuditLog(f, podLabelSelector, containerName, logPath)
	scanner := bufio.NewScanner(bytes.NewReader(logs))

	expAuditEvents := []auditv1.Event{
		{
			Level:      auditv1.LevelRequestResponse,
			Stage:      auditv1.StageRequestReceived,
			RequestURI: "/api/v1/namespaces/kube-system/pods",
			Verb:       "get",
			User: authnv1.UserInfo{
				Username: "user@example.com",
				Groups:   []string{"group-1", "group-2"},
			},
		},
		{
			Level:      auditv1.LevelRequestResponse,
			Stage:      auditv1.StageResponseComplete,
			RequestURI: "/api/v1/namespaces/kube-system/pods",
			Verb:       "get",
			User: authnv1.UserInfo{
				Username: "user@example.com",
				Groups:   []string{"group-1", "group-2"},
			},
			ResponseStatus: &metav1.Status{
				Code: 403,
			},
		},

		// From what I could tell, this could never had succeeded - even pre-fork
		// auditv1.Event{
		// 	Level:      auditv1.LevelRequestResponse,
		// 	Stage:      auditv1.StageResponseStarted,
		// 	RequestURI: "/api/v1/namespaces/kube-system/pods",
		// 	Verb:       "get",
		// 	ResponseStatus: &metav1.Status{
		// 		Code:    401,
		// 		Message: "Authentication failed, attempted: bearer",
		// 	},
		// },
	}

	By("Testing for expected audit logs")
	var i int
	for scanner.Scan() {
		if i > len(expAuditEvents) {
			Expect(fmt.Errorf("more proxy audit logs than expected, exp=%d got=%s", len(expAuditEvents), logs)).NotTo(HaveOccurred())
		}

		var auditEvent auditv1.Event
		err = json.Unmarshal(scanner.Bytes(), &auditEvent)
		Expect(err).NotTo(HaveOccurred())

		gotAuditEvent := auditv1.Event{
			Level:      auditEvent.Level,
			Stage:      auditEvent.Stage,
			RequestURI: auditEvent.RequestURI,
			Verb:       auditEvent.Verb,
			User: authnv1.UserInfo{
				Username: auditEvent.User.Username,
				Groups:   auditEvent.User.Groups,
			},
		}

		if auditEvent.ResponseStatus != nil {
			gotAuditEvent.ResponseStatus = &metav1.Status{
				Code:    auditEvent.ResponseStatus.Code,
				Message: auditEvent.ResponseStatus.Message,
			}
		}

		if !reflect.DeepEqual(expAuditEvents[i], gotAuditEvent) {
			Expect(fmt.Errorf("unexpected audit event\nexp=%v\ngot=%v", expAuditEvents[i], gotAuditEvent)).NotTo(HaveOccurred())
		}

		i++
	}

	if i != len(expAuditEvents) {
		Expect(fmt.Errorf("less proxy audit logs then expected, exp=%d, got=%s", len(expAuditEvents), logs)).NotTo(HaveOccurred())
	}
}
