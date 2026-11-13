// Copyright Jetstack Ltd. See LICENSE for details.

//go:build e2e

package upgrade

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
	"k8s.io/client-go/tools/portforward"
	"k8s.io/client-go/tools/remotecommand"
	"k8s.io/client-go/transport/spdy"

	// required to register oidc auth plugin for rest client
	_ "k8s.io/client-go/plugin/pkg/client/auth/oidc"

	"github.com/rafpe/kube-oidc-proxy/test/e2e/framework"
	"github.com/rafpe/kube-oidc-proxy/test/kind"
	"github.com/rafpe/kube-oidc-proxy/test/util/port"
)

// Both specs stream through the same default proxy deployment to the same echo
// server pod without mutating it, so the deploy and the echo server setup are
// shared. The setup has to be shared rather than per-spec: the Role and
// RoleBinding below have fixed names and are never deleted, so recreating them
// for a second spec in the same namespace would fail as already existing.
var _ = framework.CasesDescribe("Upgrade", Ordered, ContinueOnFailure, Label("shard-b"), func() {
	f := framework.NewOrderedDefaultFramework("upgrade")

	var pod *corev1.Pod
	BeforeAll(func(ctx SpecContext) {
		By("Deploying echo server to exec to")

		var err error
		pod, err = f.Helper().KubeClient.CoreV1().Pods(f.Namespace.Name).Create(ctx, &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: "echoserver-",
			},
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{
					{
						Name:            "echoserver",
						Image:           kind.EchoServerImageName,
						ImagePullPolicy: corev1.PullNever,
						// Without a readiness probe the pod is Ready the moment
						// the process starts, and the exec case raced it to the
						// listening socket (curl exit 7 in runs 33990317402 and
						// 35720045694). Ready now means listening.
						ReadinessProbe: &corev1.Probe{
							ProbeHandler: corev1.ProbeHandler{
								HTTPGet: &corev1.HTTPGetAction{
									Path: "/ready",
									Port: intstr.FromInt32(8080),
								},
							},
							PeriodSeconds: 1,
						},
					},
				},
			},
		}, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())

		err = f.Helper().WaitForPodReady(ctx, f.Namespace.Name, pod.Name, time.Second*30)
		Expect(err).NotTo(HaveOccurred())

		By("Creating Role")
		_, err = f.Helper().KubeClient.RbacV1().Roles(f.Namespace.Name).Create(ctx, &rbacv1.Role{
			ObjectMeta: metav1.ObjectMeta{
				Name: "e2e-test-exec",
			},
			Rules: []rbacv1.PolicyRule{
				{
					APIGroups: []string{""},
					Resources: []string{
						"pods", "pods/exec", "pods/portforward",
					},
					Verbs: []string{
						"get", "list", "create",
					},
				},
			},
		}, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())

		By("Creating RoleBinding")
		_, err = f.Helper().KubeClient.RbacV1().RoleBindings(f.Namespace.Name).Create(ctx,
			&rbacv1.RoleBinding{
				ObjectMeta: metav1.ObjectMeta{
					Name: "e2e-test-exec",
				},
				Subjects: []rbacv1.Subject{
					{
						Name: "user@example.com",
						Kind: "User",
					},
				},
				RoleRef: rbacv1.RoleRef{
					Name: "e2e-test-exec",
					Kind: "Role",
				},
			}, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())
	})

	It("should be able to exec into pod through the proxy", func(ctx SpecContext) {
		restConfig := newRestConfig(f)

		restClient, err := rest.RESTClientFor(restConfig)
		Expect(err).NotTo(HaveOccurred())

		// curl echo server from within pod
		req := restClient.Post().
			Resource("pods").
			Name(pod.Name).
			Namespace(pod.Namespace).
			SubResource("exec").
			VersionedParams(&corev1.PodExecOptions{
				Container: "echoserver",
				Command: []string{
					"curl", "127.0.0.1:8080", "-s", "-d", "hello world",
				},
				Stdin:  false,
				Stdout: true,
				Stderr: true,
				TTY:    false,
			}, scheme.ParameterCodec)

		exec, err := remotecommand.NewSPDYExecutor(restConfig, "POST", req.URL())
		Expect(err).NotTo(HaveOccurred())

		execOut := &bytes.Buffer{}
		execErr := &bytes.Buffer{}

		sopt := remotecommand.StreamOptions{
			Stdout: execOut,
			Stderr: execErr,
			Tty:    false,
		}

		By("Running exec into pod and runing curl on local host")
		err = exec.StreamWithContext(ctx, sopt)
		Expect(err).NotTo(HaveOccurred())

		// should have no stderr output
		if execErr.String() != "" {
			err := fmt.Errorf("got curl error: %s", execErr.String())
			Expect(err).NotTo(HaveOccurred())
		}

		By(fmt.Sprintf("exec output %s/%s: %s", pod.Namespace, pod.Name, execOut.String()))

		// should have correct stdout output from echo server
		if !strings.Contains(execOut.String(), "Request Body:\nhello world") {
			err := fmt.Errorf("got unexpected echoserver response: exp=Request Body:\\nhello world got=%s",
				execOut.String())
			Expect(err).NotTo(HaveOccurred())
		}
	})

	It("it should be able to sustain a port forward to send traffic", func() {
		By("Creating a port forward")

		portOut := &bytes.Buffer{}
		portErr := &bytes.Buffer{}

		freePort, err := port.Free()
		Expect(err).NotTo(HaveOccurred())

		restConfig := newRestConfig(f)

		restClient, err := rest.RESTClientFor(restConfig)
		Expect(err).NotTo(HaveOccurred())

		req := restClient.Post().
			Resource("pods").
			Namespace(pod.Namespace).
			Name(pod.Name).
			SubResource("portforward")

		pfopts := &portForwardOptions{
			address:    []string{"127.0.0.1"},
			ports:      []string{freePort + ":8080"},
			stopCh:     make(chan struct{}, 1),
			readyCh:    make(chan struct{}),
			outBuf:     portOut,
			errBuf:     portErr,
			restConfig: restConfig,
		}

		errCh := make(chan error, 1)

		go func() {
			// Closing stopCh ends the port forward, which is what lets
			// forwardPorts below return once the request has been checked.
			defer close(pfopts.stopCh)
			errCh <- curlThroughPortForward(freePort, pfopts.readyCh)
		}()

		By("Running port forward")
		Expect(forwardPorts("POST", req.URL(), pfopts)).To(Succeed())
		Expect(<-errCh).To(Succeed())
	})
})

// curlThroughPortForward waits for the port forward to report ready, then
// posts a body through it to the echo server and checks it comes back.
func curlThroughPortForward(localPort string, readyCh <-chan struct{}) error {
	select {
	case <-readyCh:
	case <-time.After(30 * time.Second):
		return errors.New("port forward did not become ready within 30s")
	}

	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			DisableKeepAlives: true,
		},
	}

	resp, err := client.Post(fmt.Sprintf("http://127.0.0.1:%s", localPort), "", strings.NewReader("hello world"))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("got unexpected response code from server, exp=200 got=%d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read body: %w", err)
	}

	// The echo server answers with the request it received.
	if !bytes.Contains(body, []byte("Request Body:\nhello world")) {
		return fmt.Errorf("got unexpected echoserver response: exp=...hello world got=%s", body)
	}

	return nil
}

type portForwardOptions struct {
	address, ports  []string
	readyCh, stopCh chan struct{}
	outBuf, errBuf  *bytes.Buffer
	restConfig      *rest.Config
}

func forwardPorts(method string, url *url.URL, opts *portForwardOptions) error {
	transport, upgrader, err := spdy.RoundTripperFor(opts.restConfig)
	if err != nil {
		return err
	}
	dialer := spdy.NewDialer(upgrader, &http.Client{Transport: transport}, method, url)
	fw, err := portforward.NewOnAddresses(dialer, opts.address,
		opts.ports, opts.stopCh, opts.readyCh, opts.outBuf, opts.errBuf)
	if err != nil {
		return err
	}

	return fw.ForwardPorts()
}

func newRestConfig(f *framework.Framework) *rest.Config {
	return &rest.Config{
		Host: f.ProxyURL().Host,
		AuthProvider: &clientcmdapi.AuthProviderConfig{
			Name: "oidc",
			Config: map[string]string{
				"client-id":      f.ClientID(),
				"id-token":       f.SignedToken(),
				"idp-issuer-url": f.IssuerURL().String(),
			},
		},
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
