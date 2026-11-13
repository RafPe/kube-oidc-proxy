// Copyright Jetstack Ltd. See LICENSE for details.

//go:build e2e

package framework

import (
	"context"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
)

const (
	clientID = "kube-oidc-proxy-e2e-client_id"
)

// CreateKubeNamespace creates a new Kubernetes Namespace for a test.
func (f *Framework) CreateKubeNamespace(ctx context.Context, baseName string) (*corev1.Namespace, error) {
	ns := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: fmt.Sprintf("kube-oidc-proxy-e2e-%v-", baseName),
		},
	}

	return f.helper.KubeClient.CoreV1().Namespaces().Create(ctx, ns, metav1.CreateOptions{})
}

// DeleteKubeNamespace will delete a namespace resource
func (f *Framework) DeleteKubeNamespace(ctx context.Context, namespace string) error {
	return f.helper.KubeClient.CoreV1().Namespaces().Delete(ctx, namespace, metav1.DeleteOptions{})
}

// WaitForKubeNamespaceNotExist will wait for the namespace with the given name
// to not exist for up to 2 minutes.
func (f *Framework) WaitForKubeNamespaceNotExist(ctx context.Context, namespace string) error {
	return wait.PollUntilContextTimeout(ctx, time.Second*2, time.Minute*2, true,
		namespaceNotExist(f.helper.KubeClient, namespace))
}

func namespaceNotExist(c kubernetes.Interface, namespace string) wait.ConditionWithContextFunc {
	return func(ctx context.Context) (bool, error) {
		_, err := c.CoreV1().Namespaces().Get(ctx, namespace, metav1.GetOptions{})
		if apierrors.IsNotFound(err) {
			return true, nil
		}
		if err != nil {
			return false, err
		}
		return false, nil
	}
}
