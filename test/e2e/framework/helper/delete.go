// Copyright Jetstack Ltd. See LICENSE for details.
package helper

import (
	"context"

	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/rafpe/kube-oidc-proxy/test/kind"
)

func (h *Helper) DeleteProxy(ctx context.Context, ns string) error {
	return h.deleteApp(ctx, ns, kind.ProxyImageName, "oidc-ca")
}

func (h *Helper) DeleteIssuer(ctx context.Context, ns string) error {
	return h.DeleteNamedIssuer(ctx, ns, kind.IssuerImageName)
}

func (h *Helper) DeleteNamedIssuer(ctx context.Context, ns, name string) error {
	return h.deleteApp(ctx, ns, name)
}

func (h *Helper) DeleteFakeAPIServer(ctx context.Context, ns string) error {
	return h.deleteApp(ctx, ns, kind.FakeAPIServerImageName)
}

func (h *Helper) deleteApp(ctx context.Context, ns, name string, extraSecrets ...string) error {
	err := h.KubeClient.AppsV1().Deployments(ns).Delete(ctx, name, metav1.DeleteOptions{})
	if err != nil && !k8sErrors.IsNotFound(err) {
		return err
	}

	for _, s := range append(extraSecrets, name) {
		err = h.KubeClient.CoreV1().Secrets(ns).Delete(ctx, s, metav1.DeleteOptions{})
		if err != nil && !k8sErrors.IsNotFound(err) {
			return err
		}
	}

	err = h.KubeClient.CoreV1().Services(ns).Delete(ctx, name, metav1.DeleteOptions{})
	if err != nil && !k8sErrors.IsNotFound(err) {
		return err
	}

	err = h.KubeClient.CoreV1().ServiceAccounts(ns).Delete(ctx, name, metav1.DeleteOptions{})
	if err != nil && !k8sErrors.IsNotFound(err) {
		return err
	}

	return nil
}
