// Copyright Jetstack Ltd. See LICENSE for details.
package helper

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/url"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"

	"github.com/rafpe/kube-oidc-proxy/internal/devkit/appdeploy"
)

func (h *Helper) WaitForDeploymentReady(ctx context.Context, namespace, name string, timeout time.Duration) error {
	slog.Info("helper: waiting for deployment to become ready", slog.String("namespace", namespace), slog.String("name", name))

	err := wait.PollUntilContextTimeout(ctx, time.Second*2, timeout, true, func(ctx context.Context) (bool, error) {
		return h.DeploymentReady(ctx, namespace, name)
	})

	if err != nil {
		return h.describeDeploymentFailure(ctx, namespace, name, err)
	}

	return nil
}

// describeDeploymentFailure wraps a deployment wait error with the state of
// the Deployment, its Pods and the namespace events, written to the test
// output. The Deployment alone rarely explains a timeout: a pod stuck in
// ContainerCreating only shows up in the pod description and the events.
func (h *Helper) describeDeploymentFailure(ctx context.Context, namespace, name string, err error) error {
	kubectl := h.Kubectl(namespace)

	if kErr := kubectl.DescribeResource("deployment", name); kErr != nil {
		err = fmt.Errorf("%s\n%s", err, kErr)
	}

	selector := "app=" + name
	if deploy, gErr := h.KubeClient.AppsV1().Deployments(namespace).Get(ctx, name, metav1.GetOptions{}); gErr == nil && deploy.Spec.Selector != nil {
		if sel, sErr := metav1.LabelSelectorAsSelector(deploy.Spec.Selector); sErr == nil && !sel.Empty() {
			selector = sel.String()
		}
	}
	if kErr := kubectl.Run("describe", "pods", "-l", selector); kErr != nil {
		err = fmt.Errorf("%s\n%s", err, kErr)
	}

	if kErr := kubectl.Run("get", "events", "--sort-by=.lastTimestamp"); kErr != nil {
		err = fmt.Errorf("%s\n%s", err, kErr)
	}

	return err
}

// DeploymentReady reports whether every desired replica of the Deployment is
// ready right now, for checks that the state holds over time rather than that
// it is eventually reached.
func (h *Helper) DeploymentReady(ctx context.Context, namespace, name string) (bool, error) {
	return appdeploy.DeploymentReady(ctx, h.KubeClient, namespace, name)
}

// WaitForServiceEndpoints waits until the Service has at least one ready
// endpoint, which is when its cluster DNS name starts routing to a pod. A ready
// Deployment alone does not mean that: the EndpointSlice controller publishes
// the pod as an endpoint asynchronously.
func (h *Helper) WaitForServiceEndpoints(ctx context.Context, namespace, service string, timeout time.Duration) error {
	slog.Info("helper: waiting for service endpoints", slog.String("namespace", namespace), slog.String("name", service))

	err := wait.PollUntilContextTimeout(ctx, time.Second, timeout, true, func(ctx context.Context) (bool, error) {
		return appdeploy.ServiceHasReadyEndpoint(ctx, h.KubeClient, namespace, service)
	})
	if err != nil {
		return fmt.Errorf("service %s/%s has no ready endpoint: %w", namespace, service, err)
	}

	return nil
}

// WaitForTLSHandshake waits until a TLS handshake with u's host succeeds and
// the server presents a certificate that certPEM verifies. A bare TCP dial is
// not enough for a port kind maps to the host: Docker's proxy accepts the
// connection whether or not anything behind it is serving.
func (h *Helper) WaitForTLSHandshake(ctx context.Context, u *url.URL, certPEM []byte, timeout time.Duration) error {
	slog.Info("helper: waiting for TLS handshake", slog.String("url", u.String()))

	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(certPEM) {
		return errors.New("no certificate in the PEM to verify the TLS handshake against")
	}
	dialer := &tls.Dialer{
		NetDialer: &net.Dialer{Timeout: 5 * time.Second},
		Config:    &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12},
	}

	var lastErr error
	err := wait.PollUntilContextTimeout(ctx, time.Second, timeout, true, func(ctx context.Context) (bool, error) {
		conn, err := dialer.DialContext(ctx, "tcp", u.Host)
		if err != nil {
			lastErr = err
			return false, nil
		}
		_ = conn.Close()
		return true, nil
	})
	if err != nil {
		return fmt.Errorf("no TLS handshake with %s (last error: %v): %w", u.Host, lastErr, err)
	}

	return nil
}

func (h *Helper) WaitForPodReady(ctx context.Context, namespace, name string, timeout time.Duration) error {
	slog.Info("helper: waiting for pod to become ready", slog.String("namespace", namespace), slog.String("name", name))

	err := wait.PollUntilContextTimeout(ctx, time.Second*2, timeout, true, func(ctx context.Context) (bool, error) {
		pod, err := h.KubeClient.CoreV1().Pods(namespace).Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			return false, err
		}

		if len(pod.Status.Conditions) == 0 {
			return false, nil
		}

		var ready bool
		for _, cond := range pod.Status.Conditions {
			if cond.Type == corev1.PodReady &&
				cond.Status == corev1.ConditionTrue {
				ready = true
				break
			}
		}

		if !ready {
			slog.Info("helper: pod not ready",
				slog.String("namespace", pod.Namespace), slog.String("name", pod.Name), slog.Any("conditions", pod.Status.Conditions))
			return false, nil
		}

		return true, nil
	})
	if err != nil {
		kErr := h.Kubectl(namespace).DescribeResource("pod", name)
		if kErr != nil {
			err = fmt.Errorf("%w\n%w", err, kErr)
		}

		return err
	}

	return nil
}

func (h *Helper) WaitForDeploymentToDelete(ctx context.Context, namespace, name string, timeout time.Duration) error {
	slog.Info("helper: waiting for deployment to be deleted", slog.String("namespace", namespace), slog.String("name", name))

	err := wait.PollUntilContextTimeout(ctx, time.Second*2, timeout, true, func(ctx context.Context) (bool, error) {
		_, err := h.KubeClient.AppsV1().Deployments(namespace).Get(ctx, name, metav1.GetOptions{})
		if k8sErrors.IsNotFound(err) {
			slog.Info("helper: deployment deleted, waiting for pods", slog.String("namespace", namespace), slog.String("name", name))
			pods, err := h.KubeClient.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{})

			if err != nil {
				return false, nil
			}

			for _, pod := range pods.Items {
				if strings.HasPrefix(pod.Name, name+"-") {
					slog.Info("helper: pod still not terminated", slog.String("namespace", namespace), slog.String("name", pod.Name))
					return false, nil
				}
			}

			slog.Info("helper: all pods terminated", slog.String("namespace", namespace), slog.String("name", name))
			return true, nil
		}

		if err != nil {
			return false, nil
		}

		return false, nil
	})

	if err != nil {
		kErr := h.Kubectl(namespace).DescribeResource("deployment", name)
		if kErr != nil {
			err = fmt.Errorf("%w\n%w", err, kErr)
		}

		return err
	}

	return nil
}

func (h *Helper) WaitForURLToBeReady(ctx context.Context, url *url.URL, timeout time.Duration) error {
	slog.Info("helper: waiting for URL to be ready", slog.String("url", url.String()))

	return wait.PollUntilContextTimeout(ctx, time.Second*2, timeout, true, func(ctx context.Context) (bool, error) {
		host := url.Host
		port := url.Port()
		tocheck := host

		if port != "" {
			tocheck = tocheck + ":" + port
		}

		con, err := net.DialTimeout("tcp", tocheck, timeout)
		if err != nil {
			return false, nil
		}
		con.Close()
		return true, nil
	})
}
