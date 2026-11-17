// Copyright Jetstack Ltd. See LICENSE for details.
package appdeploy

import (
	"context"
	"slices"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func TestCreateClusterIPApp(t *testing.T) {
	ctx := context.Background()
	client := fake.NewClientset()

	bundle, appURL, err := Create(ctx, client, Issuer("ns", "issuer", "oidc-issuer-e2e"))
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	if got, want := appURL.String(), "https://issuer.ns.svc.cluster.local:6443"; got != want {
		t.Errorf("URL = %q, want %q", got, want)
	}
	if len(bundle.CertBytes) == 0 || len(bundle.KeyBytes) == 0 {
		t.Error("Create() returned an empty serving bundle")
	}

	svc, err := client.CoreV1().Services("ns").Get(ctx, "issuer", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("Service not created: %v", err)
	}
	if svc.Spec.Type != corev1.ServiceTypeClusterIP || svc.Spec.Ports[0].NodePort != 0 {
		t.Errorf("Service = %s with node port %d, want ClusterIP without one", svc.Spec.Type, svc.Spec.Ports[0].NodePort)
	}

	secret, err := client.CoreV1().Secrets("ns").Get(ctx, "issuer", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("Secret not created: %v", err)
	}
	if string(secret.Data["cert.pem"]) != string(bundle.CertBytes) {
		t.Error("Secret does not hold the returned serving certificate")
	}

	if _, err := client.CoreV1().ServiceAccounts("ns").Get(ctx, "issuer", metav1.GetOptions{}); err != nil {
		t.Errorf("ServiceAccount not created: %v", err)
	}

	deploy, err := client.AppsV1().Deployments("ns").Get(ctx, "issuer", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("Deployment not created: %v", err)
	}
	args := deploy.Spec.Template.Spec.Containers[0].Args
	if !slices.Contains(args, "--issuer-url=https://issuer.ns.svc.cluster.local:6443") {
		t.Errorf("issuer args %v do not announce the Service URL", args)
	}
	if !slices.ContainsFunc(deploy.Spec.Template.Spec.Volumes, func(v corev1.Volume) bool {
		return v.Name == "tls" && v.Secret != nil && v.Secret.SecretName == "issuer"
	}) {
		t.Error("Deployment does not mount the serving certificate Secret as the tls volume")
	}
}

func TestCreateNodePortApp(t *testing.T) {
	ctx := context.Background()
	client := fake.NewClientset()

	_, appURL, err := Create(ctx, client, App{
		Namespace:   "ns",
		Name:        "proxy",
		ServiceType: corev1.ServiceTypeNodePort,
		NodePort:    31443,
	})
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	// A NodePort app is reached from the host through the pinned node port.
	if got, want := appURL.String(), "https://127.0.0.1:31443"; got != want {
		t.Errorf("URL = %q, want %q", got, want)
	}
}
