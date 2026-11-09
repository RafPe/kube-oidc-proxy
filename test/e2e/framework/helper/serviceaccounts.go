// Copyright Jetstack Ltd. See LICENSE for details.
package helper

import (
	"context"
	"fmt"

	authnv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// GetServiceAccountToken returns a short-lived token for the ServiceAccount
// ns/name, minted through the TokenRequest API. Every supported Kubernetes
// version is 1.24 or later, where ServiceAccounts no longer get a long-lived
// token Secret, so TokenRequest is the only source.
func (h *Helper) GetServiceAccountToken(ns, name string) (string, error) {
	expirationSeconds := int64(600)

	tr, err := h.KubeClient.CoreV1().ServiceAccounts(ns).CreateToken(context.TODO(), name, &authnv1.TokenRequest{
		Spec: authnv1.TokenRequestSpec{
			Audiences:         []string{"https://kubernetes.default.svc.cluster.local"},
			ExpirationSeconds: &expirationSeconds,
		},
	}, metav1.CreateOptions{})
	if err != nil {
		return "", fmt.Errorf("requesting a token for ServiceAccount %s/%s: %w", ns, name, err)
	}

	return tr.Status.Token, nil
}
