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
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	authnv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	auditv1 "k8s.io/apiserver/pkg/apis/audit/v1"

	"github.com/rafpe/kube-oidc-proxy/test/e2e/framework"
	"github.com/rafpe/kube-oidc-proxy/test/e2e/framework/helper"
	"github.com/rafpe/kube-oidc-proxy/test/kind"
)

const (
	// The proxy image is distroless and runs as nonroot, so the audit log has
	// to be written to a writable emptyDir rather than the root filesystem, and
	// read back through a sidecar since the proxy image has no shell or cat.
	auditLogDir      = "/var/log/kube-oidc-proxy"
	auditLogPath     = auditLogDir + "/audit.log"
	auditLogVolume   = "audit-log"
	auditReaderName  = "audit-reader"
	webhookAuditPath = "/audit-log"
)

var _ = framework.CasesDescribe("Audit", func() {
	f := framework.NewDefaultFramework("audit")

	It("should be able to write audit logs to file", func() {
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
		// has cat), runs as root (so it can read the 0600 log written by the
		// proxy) and is already loaded into the kind nodes.
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

		testAuditLogs(f, "app=kube-oidc-proxy-e2e", auditReaderName, auditLogPath)
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
	// Get pod
	pods, err := f.Helper().KubeClient.CoreV1().Pods(f.Namespace.Name).List(context.TODO(), metav1.ListOptions{
		LabelSelector: podLabelSelector,
	})
	Expect(err).NotTo(HaveOccurred())
	if len(pods.Items) != 1 {
		Expect(fmt.Errorf("expected single kube-oidc-proxy pod running, got=%d", len(pods.Items))).NotTo(HaveOccurred())
	}

	execArgs := []string{"exec", pods.Items[0].Name}
	if containerName != "" {
		execArgs = append(execArgs, "-c", containerName)
	}
	execArgs = append(execArgs, "--", "cat", logPath)

	var auditLogsBuffer bytes.Buffer
	err = f.Helper().Kubectl(f.Namespace.Name).RunWithStdout(&auditLogsBuffer, execArgs...)
	Expect(err).NotTo(HaveOccurred())

	logs := auditLogsBuffer.Bytes()
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
