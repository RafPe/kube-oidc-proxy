// Copyright Jetstack Ltd. See LICENSE for details.
package helper

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"

	"github.com/rafpe/kube-oidc-proxy/internal/devkit/appdeploy"
	"github.com/rafpe/kube-oidc-proxy/internal/devkit/keybundle"
	"github.com/rafpe/kube-oidc-proxy/test/kind"
)

// ProxyExtras holds additions to the proxy pod that cannot be expressed with
// extraVolumes, which are always mounted read only at /<volume name>. Volumes
// are paired with explicit VolumeMounts on the proxy container, and Containers
// are added to the pod as sidecars, typically to share one of those volumes.
type ProxyExtras struct {
	Volumes      []corev1.Volume
	VolumeMounts []corev1.VolumeMount
	Containers   []corev1.Container
	// Ports are added to the proxy container, so a test can give it the named
	// port the chart renders.
	Ports []corev1.ContainerPort
}

func (h *Helper) DeployProxy(ctx context.Context, ns *corev1.Namespace, issuerURL *url.URL, clientID string,
	oidcKeyBundle *keybundle.Bundle, extraVolumes []corev1.Volume, extraArgs ...string) (*keybundle.Bundle, *url.URL, error) {
	return h.DeployProxyWithExtras(ctx, ns, issuerURL, clientID, oidcKeyBundle, extraVolumes, nil, extraArgs...)
}

func (h *Helper) DeployProxyWithExtras(ctx context.Context, ns *corev1.Namespace, issuerURL *url.URL, clientID string,
	oidcKeyBundle *keybundle.Bundle, extraVolumes []corev1.Volume, extras *ProxyExtras, extraArgs ...string) (*keybundle.Bundle, *url.URL, error) {
	authConfig := false
	for _, a := range extraArgs {
		if strings.HasPrefix(a, "--authentication-config") {
			authConfig = true
			break
		}
	}

	args := []string{
		"kube-oidc-proxy",
		"--secure-port=6443",
		"--tls-cert-file=/tls/cert.pem",
		"--tls-private-key-file=/tls/key.pem",
	}
	if !authConfig {
		args = append(args,
			fmt.Sprintf("--oidc-client-id=%s", clientID),
			fmt.Sprintf("--oidc-issuer-url=%s", issuerURL),
			"--oidc-username-claim=email",
			"--oidc-groups-claim=groups",
			"--oidc-ca-file=/oidc/ca.pem",
			"--oidc-ca-file=/oidc/ca.pem",
		)
	}
	args = append(args, "--v=10")
	args = append(args, extraArgs...)

	volumeMounts := []corev1.VolumeMount{
		{
			MountPath: "/tls",
			Name:      "tls",
			ReadOnly:  true,
		},
	}
	if !authConfig {
		volumeMounts = append(volumeMounts, corev1.VolumeMount{
			MountPath: "/oidc",
			Name:      "oidc",
			ReadOnly:  true,
		})
	}

	cnt := corev1.Container{
		Name:            kind.ProxyImageName,
		Image:           kind.ProxyImageName,
		ImagePullPolicy: corev1.PullNever,
		Args:            args,
		VolumeMounts:    volumeMounts,
		Ports: []corev1.ContainerPort{
			{
				ContainerPort: 6443,
			},
			{
				ContainerPort: 8080,
			},
		},
		ReadinessProbe: &corev1.Probe{
			ProbeHandler: corev1.ProbeHandler{
				HTTPGet: &corev1.HTTPGetAction{
					Path: "/ready",
					Port: intstr.FromInt(8080),
				},
			},
			InitialDelaySeconds: 1,
			PeriodSeconds:       3,
		},
	}

	for _, v := range extraVolumes {
		cnt.VolumeMounts = append(cnt.VolumeMounts, corev1.VolumeMount{
			MountPath: fmt.Sprintf("/%s", v.Name),
			Name:      v.Name,
			ReadOnly:  true,
		})
	}

	volumes := extraVolumes
	if extras != nil {
		cnt.VolumeMounts = append(cnt.VolumeMounts, extras.VolumeMounts...)
		cnt.Ports = append(cnt.Ports, extras.Ports...)
		volumes = append(volumes, extras.Volumes...)
	}

	containers := []corev1.Container{cnt}
	if extras != nil {
		containers = append(containers, extras.Containers...)
	}

	if !authConfig {
		volumes = append(volumes, corev1.Volume{
			Name: "oidc",
			VolumeSource: corev1.VolumeSource{
				Secret: &corev1.SecretVolumeSource{
					SecretName: "oidc-ca",
				},
			},
		})

		sec := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "oidc-ca",
				Namespace: ns.Name,
			},
			Data: map[string][]byte{
				"ca.pem": oidcKeyBundle.CertBytes,
			},
		}

		if _, err := h.KubeClient.CoreV1().Secrets(ns.Name).Create(ctx, sec, metav1.CreateOptions{}); err != nil {
			return nil, nil, err
		}
	}

	// Pin the NodePort so it lines up with the kind node's extraPortMappings
	// entry, making the proxy reachable at https://127.0.0.1:<ProxyNodePort>
	// from the host. Only one proxy exists at a time (AfterEach deletes it) so
	// there is no NodePort collision.
	bundle, appURL, err := h.deployApp(ctx, appdeploy.App{
		Namespace:   ns.Name,
		Name:        kind.ProxyImageName,
		ServiceType: corev1.ServiceTypeNodePort,
		NodePort:    kind.ProxyNodePort,
		Containers:  containers,
		Volumes:     volumes,
	})
	if err != nil {
		return nil, nil, err
	}

	pTrue := true
	pFalse := false

	// The proxy's own permissions come from the Helm chart, rendered with the
	// suite's values file, not from a copy kept here. A permission the proxy
	// needs but the chart does not grant therefore fails the suite, which is
	// the artefact operators install.
	chartRules, err := ChartClusterRoleRules(h.cfg.RepoRoot, ChartRBACValuesFile)
	if err != nil {
		return nil, nil, err
	}

	crole, err := h.KubeClient.RbacV1().ClusterRoles().Create(ctx, &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: kind.ProxyImageName + "-",
			OwnerReferences: []metav1.OwnerReference{
				{
					APIVersion:         "core/v1",
					BlockOwnerDeletion: &pTrue,
					Controller:         &pFalse,
					Kind:               "Namespace",
					Name:               ns.Name,
					UID:                ns.UID,
				},
			},
		},
		Rules: chartRules,
	}, metav1.CreateOptions{})
	if err != nil {
		return nil, nil, err
	}

	// Create a role that will allow a user to impersonate another user
	croleImpersonate, err := h.KubeClient.RbacV1().ClusterRoles().Create(ctx, &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: kind.ProxyImageName + "-impersonate-",
			OwnerReferences: []metav1.OwnerReference{
				{
					APIVersion:         "core/v1",
					BlockOwnerDeletion: &pTrue,
					Controller:         &pFalse,
					Kind:               "Namespace",
					Name:               ns.Name,
					UID:                ns.UID,
				},
			},
		},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups:     []string{""},
				Resources:     []string{"users"},
				ResourceNames: []string{"ok-to-impersonate@nodomain.dev"},
				Verbs:         []string{"impersonate"},
			},
			{
				APIGroups:     []string{""},
				Resources:     []string{"groups"},
				ResourceNames: []string{"ok-to-impersonate-group"},
				Verbs:         []string{"impersonate"},
			},
			{
				APIGroups:     []string{"authentication.k8s.io"},
				Resources:     []string{"userextras/oktoimpersonateextra"},
				ResourceNames: []string{"foo"},
				Verbs:         []string{"impersonate"},
			},
		},
	}, metav1.CreateOptions{})
	if err != nil {
		return nil, nil, err
	}

	// Create a ClusterRoleBinding so the user can impersonate test users

	_, err = h.KubeClient.RbacV1().ClusterRoleBindings().Create(ctx,
		&rbacv1.ClusterRoleBinding{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: kind.ProxyImageName + "-impersonate-",
				OwnerReferences: []metav1.OwnerReference{
					{
						APIVersion:         "core/v1",
						BlockOwnerDeletion: &pTrue,
						Controller:         &pFalse,
						Kind:               "Namespace",
						Name:               ns.Name,
						UID:                ns.UID,
					},
				},
			},
			RoleRef: rbacv1.RoleRef{
				Name: croleImpersonate.Name, Kind: "ClusterRole",
			},
			Subjects: []rbacv1.Subject{
				{Name: "user@example.com", Kind: "User"},
			},
		}, metav1.CreateOptions{})
	if err != nil {
		return nil, nil, err
	}

	_, err = h.KubeClient.RbacV1().ClusterRoleBindings().Create(ctx,
		&rbacv1.ClusterRoleBinding{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: kind.ProxyImageName + "-",
				OwnerReferences: []metav1.OwnerReference{
					{
						APIVersion:         "core/v1",
						BlockOwnerDeletion: &pTrue,
						Controller:         &pFalse,
						Kind:               "Namespace",
						Name:               ns.Name,
						UID:                ns.UID,
					},
				},
			},
			RoleRef: rbacv1.RoleRef{
				Name: crole.Name, Kind: "ClusterRole",
			},
			Subjects: []rbacv1.Subject{
				{Name: kind.ProxyImageName, Namespace: ns.Name, Kind: "ServiceAccount"},
			},
		}, metav1.CreateOptions{})
	if err != nil {
		return nil, nil, err
	}

	return bundle, appURL, nil
}

func (h *Helper) DeployIssuer(ctx context.Context, ns string) (*keybundle.Bundle, *url.URL, error) {
	return h.DeployNamedIssuer(ctx, ns, kind.IssuerImageName)
}

func (h *Helper) DeployNamedIssuer(ctx context.Context, ns, name string) (*keybundle.Bundle, *url.URL, error) {
	return h.deployApp(ctx, appdeploy.Issuer(ns, name, kind.IssuerImageName))
}

// deployApp deploys app and waits until it serves where the suite reaches it.
// A failed wait describes the Deployment, so the diagnostics land in the
// failure.
func (h *Helper) deployApp(ctx context.Context, app appdeploy.App) (*keybundle.Bundle, *url.URL, error) {
	keyBundle, appURL, err := appdeploy.Create(ctx, h.KubeClient, app)
	if err != nil {
		return nil, nil, err
	}

	if err := h.WaitForDeploymentReady(ctx, app.Namespace, app.Name, h.deployReadyTimeout()); err != nil {
		return nil, nil, err
	}

	// The callers reach the app through its Service straight away, so wait
	// for the Service to route to the ready pod rather than only for the pod.
	// For a ClusterIP app (issuer, fake apiserver, webhook) the ready endpoint
	// is the last thing observable from here. A NodePort app is reached from
	// the host, through kube-proxy rules programmed after the endpoint turns
	// ready, so for it wait until a TLS handshake through that path succeeds.
	if err := h.WaitForServiceEndpoints(ctx, app.Namespace, app.Name, time.Second*30); err != nil {
		return nil, nil, err
	}
	if app.ServiceType == corev1.ServiceTypeNodePort {
		if err := h.WaitForTLSHandshake(ctx, appURL, keyBundle.CertBytes, time.Second*30); err != nil {
			return nil, nil, err
		}
	}

	return keyBundle, appURL, nil
}
