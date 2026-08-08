// Copyright Jetstack Ltd. See LICENSE for details.
package helper

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/klog/v2"
)

func (h *Helper) WaitForDeploymentReady(namespace, name string, timeout time.Duration) error {
	klog.Infof("Waiting for Deployment to become ready %s/%s", namespace, name)

	err := wait.PollUntilContextTimeout(context.Background(), time.Second*2, timeout, true, func(ctx context.Context) (bool, error) {
		deploy, err := h.KubeClient.AppsV1().Deployments(namespace).Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			return false, err
		}

		if deploy.Spec.Replicas == nil {
			return false, nil
		}

		if *deploy.Spec.Replicas == deploy.Status.ReadyReplicas {
			return true, nil
		}

		return false, nil
	})

	if err != nil {
		kErr := h.Kubectl(namespace).DescribeResource("deployment", name)
		if kErr != nil {
			err = fmt.Errorf("%s\n%s", err, kErr)
		}

		return err
	}

	return nil
}

func (h *Helper) WaitForPodReady(namespace, name string, timeout time.Duration) error {
	klog.Infof("Waiting for Pod to become ready %s/%s", namespace, name)

	err := wait.PollUntilContextTimeout(context.Background(), time.Second*2, timeout, true, func(ctx context.Context) (bool, error) {
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
			klog.Infof("helper: pod not ready %s/%s: %v",
				pod.Namespace, pod.Name, pod.Status.Conditions)
			return false, nil
		}

		return true, nil
	})
	if err != nil {
		kErr := h.Kubectl(namespace).DescribeResource("pod", name)
		if kErr != nil {
			err = fmt.Errorf("%s\n%s", err, kErr)
		}

		return err
	}

	return nil
}

func (h *Helper) WaitForDeploymentToDelete(namespace, name string, timeout time.Duration) error {
	klog.Infof("Waiting for Deployment to be deleted: %s/%s", namespace, name)

	err := wait.PollUntilContextTimeout(context.Background(), time.Second*2, timeout, true, func(ctx context.Context) (bool, error) {
		_, err := h.KubeClient.AppsV1().Deployments(namespace).Get(ctx, name, metav1.GetOptions{})
		if k8sErrors.IsNotFound(err) {
			klog.Infof("Deployment %s/%s deleted, waiting for pods", namespace, name)
			pods, err := h.KubeClient.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{})

			if err != nil {
				return false, nil
			}

			for _, pod := range pods.Items {
				if strings.HasPrefix(pod.Name, name+"-") {
					klog.Infof("Pod %s/%s still not terminated", namespace, pod.Name)
					return false, nil
				}
			}

			klog.Infof("All pods for %s/%s terminated", namespace, name)
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
			err = fmt.Errorf("%s\n%s", err, kErr)
		}

		return err
	}

	return nil
}

func (h *Helper) WaitForURLToBeReady(url *url.URL, timeout time.Duration) error {
	klog.Infof("Waiting for URL %s to be ready", url)

	return wait.PollUntilContextTimeout(context.Background(), time.Second*2, timeout, true, func(ctx context.Context) (bool, error) {
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
