// Copyright Jetstack Ltd. See LICENSE for details.
package helper

import (
	"context"
	"net/url"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/rafpe/kube-oidc-proxy/test/kind"
)

func (h *Helper) DeployFakeAPIServer(ns string) ([]corev1.Volume, *url.URL, error) {
	cnt := corev1.Container{
		Name:            kind.FakeAPIServerImageName,
		Image:           kind.FakeAPIServerImageName,
		ImagePullPolicy: corev1.PullNever,
		Args: []string{
			"fake-apiserver",
			"--secure-port=6443",
			"--tls-cert-file=/tls/cert.pem",
			"--tls-private-key-file=/tls/key.pem",
		},
		VolumeMounts: []corev1.VolumeMount{
			{
				MountPath: "/tls",
				Name:      "tls",
				ReadOnly:  true,
			},
		},
		Ports: []corev1.ContainerPort{
			{
				ContainerPort: 6443,
			},
		},
	}

	bundle, appURL, err := h.deployApp(ns, kind.FakeAPIServerImageName, corev1.ServiceTypeClusterIP, []corev1.Container{cnt})
	if err != nil {
		return nil, nil, err
	}

	sec, err := h.KubeClient.CoreV1().Secrets(ns).Create(context.TODO(), &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: "fake-apiserver-ca-",
			Namespace:    ns,
		},
		Data: map[string][]byte{
			"ca.pem": bundle.CertBytes,
		},
	}, metav1.CreateOptions{})
	if err != nil {
		return nil, nil, err
	}

	extraVolumes := []corev1.Volume{
		{
			Name: "fake-apiserver",
			VolumeSource: corev1.VolumeSource{
				Secret: &corev1.SecretVolumeSource{
					SecretName: sec.Name,
				},
			},
		},
	}

	return extraVolumes, appURL, nil
}

func (h *Helper) DeployAuditWebhook(ns, logPath string) (corev1.Volume, *url.URL, error) {
	cnt := corev1.Container{
		Name:            kind.AuditWebhookImageName,
		Image:           kind.AuditWebhookImageName,
		ImagePullPolicy: corev1.PullNever,
		Args: []string{
			"audit-webhook",
			"--secure-port=6443",
			"--tls-cert-file=/tls/cert.pem",
			"--tls-private-key-file=/tls/key.pem",
			"--audit-file-path=" + logPath,
		},
		VolumeMounts: []corev1.VolumeMount{
			{
				MountPath: "/tls",
				Name:      "tls",
				ReadOnly:  true,
			},
		},
		Ports: []corev1.ContainerPort{
			{
				ContainerPort: 6443,
			},
		},
	}

	bundle, appURL, err := h.deployApp(ns, kind.AuditWebhookImageName, corev1.ServiceTypeClusterIP, []corev1.Container{cnt})
	if err != nil {
		return corev1.Volume{}, nil, err
	}

	sec, err := h.KubeClient.CoreV1().Secrets(ns).Create(context.TODO(), &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: "audit-webhook-ca-",
			Namespace:    ns,
		},
		Data: map[string][]byte{
			"ca.pem": bundle.CertBytes,
		},
	}, metav1.CreateOptions{})
	if err != nil {
		return corev1.Volume{}, nil, err
	}

	auditWebhookCAVol := corev1.Volume{
		Name: "audit-webhook-ca",
		VolumeSource: corev1.VolumeSource{
			Secret: &corev1.SecretVolumeSource{
				SecretName: sec.Name,
			},
		},
	}

	return auditWebhookCAVol, appURL, nil
}
