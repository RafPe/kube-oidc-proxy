// Copyright Jetstack Ltd. See LICENSE for details.
package helper

import (
	"context"

	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/rafpe/kube-oidc-proxy/test/kind"
)

func (h *Helper) DeleteProxy(ns string) error {
	return h.deleteApp(ns, kind.ProxyImageName, "oidc-ca")
}

func (h *Helper) DeleteIssuer(ns string) error {
	return h.DeleteNamedIssuer(ns, kind.IssuerImageName)
}

func (h *Helper) DeleteNamedIssuer(ns, name string) error {
	return h.deleteApp(ns, name)
}

func (h *Helper) DeleteFakeAPIServer(ns string) error {
	return h.deleteApp(ns, kind.FakeAPIServerImageName)
}

func (h *Helper) deleteApp(ns, name string, extraSecrets ...string) error {
	err := h.KubeClient.AppsV1().Deployments(ns).Delete(context.TODO(), name, metav1.DeleteOptions{})
	if err != nil && !k8sErrors.IsNotFound(err) {
		return err
	}

	for _, s := range append(extraSecrets, name) {
		err = h.KubeClient.CoreV1().Secrets(ns).Delete(context.TODO(), s, metav1.DeleteOptions{})
		if err != nil && !k8sErrors.IsNotFound(err) {
			return err
		}
	}

	err = h.KubeClient.CoreV1().Services(ns).Delete(context.TODO(), name, metav1.DeleteOptions{})
	if err != nil && !k8sErrors.IsNotFound(err) {
		return err
	}

	err = h.KubeClient.CoreV1().ServiceAccounts(ns).Delete(context.TODO(), name, metav1.DeleteOptions{})
	if err != nil && !k8sErrors.IsNotFound(err) {
		return err
	}

	return nil
}
