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
	"slices"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	authnv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	auditv1 "k8s.io/apiserver/pkg/apis/audit/v1"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"

	"github.com/rafpe/kube-oidc-proxy/test/e2e/framework"
	"github.com/rafpe/kube-oidc-proxy/test/e2e/framework/helper"
	"github.com/rafpe/kube-oidc-proxy/test/e2e/suite/cases/sharedtests"
	"github.com/rafpe/kube-oidc-proxy/test/kind"
)

// deployProxyWithAuditLogFile redeploys the proxy auditing at level
// RequestResponse to a file, which is read back with readAuditLog.
func deployProxyWithAuditLogFile(ctx context.Context, f *framework.Framework) {
	By("Creating policy file ConfigMap")
	cm, err := f.Helper().KubeClient.CoreV1().ConfigMaps(f.Namespace.Name).Create(ctx, &corev1.ConfigMap{
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
	f.DeployProxyWithExtras(ctx, vols, extras,
		"--audit-log-path="+auditLogPath, "--audit-policy-file=/audit/audit.yaml")
}

// newExecRestConfig returns a rest config for streaming requests through the
// proxy. SPDY builds its own transport from TLSClientConfig, so unlike
// Framework.NewProxyRestConfig this cannot hand over a prebuilt transport.
func newExecRestConfig(f *framework.Framework) *rest.Config {
	return &rest.Config{
		Host:        f.ProxyURL().String(),
		BearerToken: f.SignedToken(),
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
func proxyPod(ctx context.Context, f *framework.Framework) *corev1.Pod {
	return singlePod(ctx, f, "app=kube-oidc-proxy-e2e")
}

// singlePod returns the only pod matching podLabelSelector, failing the spec
// if there is not exactly one.
func singlePod(ctx context.Context, f *framework.Framework, podLabelSelector string) *corev1.Pod {
	pods, err := f.Helper().KubeClient.CoreV1().Pods(f.Namespace.Name).List(ctx, metav1.ListOptions{
		LabelSelector: podLabelSelector,
	})
	Expect(err).NotTo(HaveOccurred())
	if len(pods.Items) != 1 {
		Expect(fmt.Errorf("expected single pod matching %s running, got=%d", podLabelSelector, len(pods.Items))).NotTo(HaveOccurred())
	}

	return &pods.Items[0]
}

// readAuditLog returns the contents of the audit log at logPath in the pod
// selected by podLabelSelector, read from containerName (the pod's default
// container when empty).
func readAuditLog(ctx context.Context, f *framework.Framework, podLabelSelector, containerName, logPath string) ([]byte, error) {
	pod := singlePod(ctx, f, podLabelSelector)

	execArgs := []string{"exec", pod.Name}
	if containerName != "" {
		execArgs = append(execArgs, "-c", containerName)
	}
	execArgs = append(execArgs, "--", "cat", logPath)

	var auditLogsBuffer bytes.Buffer
	if err := f.Helper().Kubectl(f.Namespace.Name).RunWithStdout(&auditLogsBuffer, execArgs...); err != nil {
		return nil, fmt.Errorf("reading audit log %s: %w", logPath, err)
	}

	return auditLogsBuffer.Bytes(), nil
}

// waitForAuditLog polls the audit log until flushed reports that every event
// the spec asserts on has been written, and returns the log. The audit
// backends batch events and write them on an interval, and the log file does
// not exist before the first write, so a read straight after the request can
// fail or see only some of the events.
func waitForAuditLog(ctx context.Context, f *framework.Framework, podLabelSelector, containerName, logPath string,
	flushed func([]auditv1.Event) bool) []byte {

	var logs []byte
	Eventually(func(g Gomega) {
		var err error
		logs, err = readAuditLog(ctx, f, podLabelSelector, containerName, logPath)
		g.Expect(err).NotTo(HaveOccurred())

		events, err := decodeAuditEvents(logs)
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(flushed(events)).To(BeTrue(), "audit log not yet flushed:\n%s", logs)
	}).WithTimeout(time.Minute).WithPolling(time.Second).Should(Succeed())

	return logs
}

// decodeAuditEvents decodes a JSON-lines audit log.
func decodeAuditEvents(logs []byte) ([]auditv1.Event, error) {
	var events []auditv1.Event
	scanner := bufio.NewScanner(bytes.NewReader(logs))
	for scanner.Scan() {
		var ev auditv1.Event
		if err := json.Unmarshal(scanner.Bytes(), &ev); err != nil {
			return nil, fmt.Errorf("decoding audit event %q: %w", scanner.Text(), err)
		}
		events = append(events, ev)
	}

	return events, scanner.Err()
}

// hasStage returns a flush condition that holds once some event whose request
// URI starts with uriPrefix has reached stage.
func hasStage(uriPrefix string, stage auditv1.Stage) func([]auditv1.Event) bool {
	return func(events []auditv1.Event) bool {
		return slices.ContainsFunc(events, func(ev auditv1.Event) bool {
			return strings.HasPrefix(ev.RequestURI, uriPrefix) && ev.Stage == stage
		})
	}
}

func testAuditLogs(ctx context.Context, f *framework.Framework, podLabelSelector, containerName, logPath string) {
	By("Making calls to proxy to ensure audit get created")
	proxyConfig := f.NewProxyRestConfig()
	requester := f.Helper().NewRequester(proxyConfig.Transport, proxyConfig.BearerToken)

	target := fmt.Sprintf("%s/api/v1/namespaces/kube-system/pods", proxyConfig.Host)

	// Make request that should succeed
	_, _, err := requester.Get(target)
	Expect(err).NotTo(HaveOccurred())

	// Make request that should be unauthenticated
	requester = f.Helper().NewRequester(proxyConfig.Transport, "foo")
	_, resp, err := requester.Get(target)
	Expect(err).NotTo(HaveOccurred())

	if resp.StatusCode != http.StatusUnauthorized {
		Expect(fmt.Errorf("expected to get unauthorized, got=%d", resp.StatusCode)).NotTo(HaveOccurred())
	}

	// A GET of a collection is the "list" verb, not "get" — "get" is a GET of a
	// single named object — and a resource request carries an objectRef naming
	// what was addressed. Both follow from the request being resolved as a
	// resource request in the core group, which is what an audit consumer
	// writes policy rules against.
	expObjectRef := &auditv1.ObjectReference{
		Resource:   "pods",
		Namespace:  "kube-system",
		APIVersion: "v1",
	}

	expAuditEvents := []auditv1.Event{
		{
			Level:      auditv1.LevelRequestResponse,
			Stage:      auditv1.StageRequestReceived,
			RequestURI: "/api/v1/namespaces/kube-system/pods",
			Verb:       "list",
			User: authnv1.UserInfo{
				Username: "user@example.com",
				Groups:   []string{"group-1", "group-2"},
			},
			ObjectRef: expObjectRef,
		},
		{
			Level:      auditv1.LevelRequestResponse,
			Stage:      auditv1.StageResponseComplete,
			RequestURI: "/api/v1/namespaces/kube-system/pods",
			Verb:       "list",
			User: authnv1.UserInfo{
				Username: "user@example.com",
				Groups:   []string{"group-1", "group-2"},
			},
			ObjectRef: expObjectRef,
			ResponseStatus: &metav1.Status{
				Code: 403,
			},
		},

		// The unauthenticated request. The failed-authentication filter
		// records a single ResponseStarted event: no identity (the request
		// was rejected before a user reached the context), the 401, and the
		// attempted authentication method. The verb and objectRef are
		// resolved because the audit chain classifies core group requests as
		// resource requests. Restored by the WithAuditInit fix
		// (TremoloSecurity/kube-oidc-proxy#92) — the previous expectation
		// here was commented out because, without an initialised audit
		// context, it could never have passed.
		{
			Level:      auditv1.LevelRequestResponse,
			Stage:      auditv1.StageResponseStarted,
			RequestURI: "/api/v1/namespaces/kube-system/pods",
			Verb:       "list",
			ObjectRef:  expObjectRef,
			ResponseStatus: &metav1.Status{
				Code:    401,
				Message: "Authentication failed, attempted: bearer",
			},
		},
	}

	By("Waiting for the audit log to hold every expected event")
	logs := waitForAuditLog(ctx, f, podLabelSelector, containerName, logPath, func(events []auditv1.Event) bool {
		return len(events) >= len(expAuditEvents)
	})
	scanner := bufio.NewScanner(bytes.NewReader(logs))

	By("Testing for expected audit logs")
	var i int
	var events []auditv1.Event
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

		if auditEvent.ObjectRef != nil {
			gotAuditEvent.ObjectRef = &auditv1.ObjectReference{
				Resource:    auditEvent.ObjectRef.Resource,
				Namespace:   auditEvent.ObjectRef.Namespace,
				Name:        auditEvent.ObjectRef.Name,
				APIGroup:    auditEvent.ObjectRef.APIGroup,
				APIVersion:  auditEvent.ObjectRef.APIVersion,
				Subresource: auditEvent.ObjectRef.Subresource,
			}
		}

		if !reflect.DeepEqual(expAuditEvents[i], gotAuditEvent) {
			Expect(fmt.Errorf("unexpected audit event\nexp=%v\ngot=%v", expAuditEvents[i], gotAuditEvent)).NotTo(HaveOccurred())
		}

		events = append(events, auditEvent)
		i++
	}

	if i != len(expAuditEvents) {
		Expect(fmt.Errorf("less proxy audit logs then expected, exp=%d, got=%s", len(expAuditEvents), logs)).NotTo(HaveOccurred())
	}

	By("Joining each audit event to the access record the proxy wrote for the same request")
	// The proxy mints the request id before anything else sees the request and
	// puts it in the Audit-ID header, which is where WithAuditInit takes the
	// event's auditID from. The two streams are therefore joinable on that one
	// value, and an audit consumer can go from an audited request to what the
	// proxy decided about it without matching on timestamps.
	//
	// Asserted against the events actually read, and only after their count has
	// been checked above, so an empty set cannot turn the join into zero
	// assertions.
	Expect(events).To(HaveLen(len(expAuditEvents)))

	// The audit log has already been read, so the proxy wrote these records
	// well before this point; the poll only covers the container runtime
	// catching up with the proxy's stdout, which is a different sink from the
	// audit log read above.
	Eventually(func() []string {
		recs, _, err := f.Helper().ProxyLogRecords(ctx, f.Namespace.Name, "app="+kind.ProxyImageName)
		Expect(err).NotTo(HaveOccurred())

		return auditIDsWithoutAccessRecord(recs, events)
	}, time.Second*20, time.Second).Should(BeEmpty(),
		"audit events whose request id has no single request.access.decided record in the proxy log")
}

// auditIDsWithoutAccessRecord returns the auditID of every event that is not
// joined to exactly one access record in recs. Exactly one, not at least one:
// a request produces a single access decision, so two records carrying the
// same request id would mean the id no longer identifies one request.
func auditIDsWithoutAccessRecord(recs []map[string]any, events []auditv1.Event) []string {
	var out []string
	for _, ev := range events {
		if len(sharedtests.ByRequestID(sharedtests.ByEvent(recs, "request.access.decided"), string(ev.AuditID))) != 1 {
			out = append(out, string(ev.AuditID))
		}
	}

	return out
}
