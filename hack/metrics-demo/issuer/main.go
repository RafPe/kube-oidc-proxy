// Copyright Jetstack Ltd. See LICENSE for details.

// Command issuer prepares the metrics demo's TLS material: it deploys the e2e
// suite's mock OIDC issuer and writes the key the load generator signs tokens
// with, and it mints the proxy's serving certificate.
//
// The serving certificate is minted here rather than left to the chart because
// the chart signs its self-generated certificate with an ephemeral CA it never
// publishes, and emits no subjectAltName: the tls.crt in that Secret is a leaf
// nothing outside the cluster can build a chain to. The demo drives the proxy
// through a port-forward on 127.0.0.1 and must verify it properly, so it
// supplies its own Secret through the chart's tls.secretName and keeps the
// issuing certificate in .state/proxy-ca.pem.
//
// Reusing helper.DeployIssuer and util.NewTLSSelfSignedCertKey means the demo
// authenticates against exactly the issuer, and trusts exactly the kind of
// certificate, that the e2e suite does.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/rafpe/kube-oidc-proxy/test/e2e/framework/config"
	"github.com/rafpe/kube-oidc-proxy/test/e2e/framework/helper"
	"github.com/rafpe/kube-oidc-proxy/test/util"
)

func main() {
	state := flag.String("state", "hack/metrics-demo/.state", "directory holding the demo's kubeconfig and generated key material")
	namespace := flag.String("namespace", "proxy", "namespace to deploy the issuer into")
	tlsSecret := flag.String("proxy-tls-secret", "kop-demo-tls", "name of the Secret to mint the proxy's serving certificate into")
	proxyService := flag.String("proxy-service", "kop-kube-oidc-proxy", "name of the proxy Service the serving certificate is issued for")
	flag.Parse()

	if err := run(*state, *namespace, *tlsSecret, *proxyService); err != nil {
		log.Fatalf("prepare demo TLS material: %s", err)
	}
}

// issuerName is the Deployment the e2e helper creates for the mock issuer.
const issuerName = "oidc-issuer-e2e"

func issuerDeployed(client kubernetes.Interface, namespace string) (bool, error) {
	_, err := client.AppsV1().Deployments(namespace).Get(context.Background(), issuerName, metav1.GetOptions{})
	switch {
	case err == nil:
		return true, nil
	case apierrors.IsNotFound(err):
		return false, nil
	default:
		return false, fmt.Errorf("failed to look up deployment %s/%s: %s", namespace, issuerName, err)
	}
}

func run(state, namespace, tlsSecret, proxyService string) error {
	kubeconfig := filepath.Join(state, "kubeconfig")

	restConfig, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		return fmt.Errorf("failed to build rest config from %q: %s", kubeconfig, err)
	}

	client, err := kubernetes.NewForConfig(restConfig)
	if err != nil {
		return fmt.Errorf("failed to build kubernetes client: %s", err)
	}

	repoRoot, err := os.Getwd()
	if err != nil {
		return err
	}

	h := helper.NewHelper(&config.Config{KubeConfigPath: kubeconfig, RepoRoot: repoRoot})
	h.KubeClient = client

	// Idempotent, so up.sh can be re-run: the issuer keeps the Deployment and
	// the key material already in .state, and only the serving certificate
	// below is (re-)checked.
	deployed, err := issuerDeployed(client, namespace)
	if err != nil {
		return err
	}

	switch {
	case deployed:
		// #nosec G304 -- state is the operator's own --state flag and the
		// file name is a constant; this is a developer tool reading what it
		// wrote itself.
		url, err := os.ReadFile(filepath.Join(state, "issuer-url"))
		if err != nil {
			return fmt.Errorf("issuer %q is deployed but its URL is not in %s; delete it and re-run: %s", issuerName, state, err)
		}
		fmt.Printf("issuer already deployed in %s at %s", namespace, url)
	default:
		bundle, issuerURL, err := h.DeployIssuer(namespace)
		if err != nil {
			return fmt.Errorf("failed to deploy issuer into %q: %s", namespace, err)
		}

		// The proxy verifies the issuer's TLS with the certificate; the load
		// generator signs tokens with the key. Both are written 0600: the key
		// mints tokens for every identity the demo uses.
		files := map[string][]byte{
			"issuer-ca.pem":  bundle.CertBytes,
			"issuer-key.pem": bundle.KeyBytes,
			"issuer-url":     []byte(issuerURL.String() + "\n"),
		}
		for name, data := range files {
			if err := os.WriteFile(filepath.Join(state, name), data, 0600); err != nil {
				return fmt.Errorf("failed to write %q: %s", name, err)
			}
		}

		fmt.Printf("issuer deployed in %s at %s\n", namespace, issuerURL)
	}

	return mintProxyCertificate(client, state, namespace, tlsSecret, proxyService)
}

// mintProxyCertificate issues the proxy's serving certificate for its
// in-cluster Service name and for 127.0.0.1, the address the load generator
// reaches it on through a port-forward, and stores it in a kubernetes.io/tls
// Secret the chart is pointed at with tls.secretName. Idempotent: an existing
// Secret is left alone, because replacing it would invalidate the
// proxy-ca.pem the demo already trusts.
func mintProxyCertificate(client kubernetes.Interface, state, namespace, name, service string) error {
	ctx := context.Background()

	existing, err := client.CoreV1().Secrets(namespace).Get(ctx, name, metav1.GetOptions{})
	if err == nil {
		// Only the certificate is written out; the key never leaves the
		// Secret and .state. A Secret that is not what the demo minted is
		// refused here rather than surfacing later as an empty trust anchor.
		cert, err := servingCertFromSecret(existing)
		if err != nil {
			return fmt.Errorf("secret %s/%s cannot be reused: %s; delete it to let the demo mint a new one", namespace, name, err)
		}
		if err := os.WriteFile(filepath.Join(state, "proxy-ca.pem"), cert, 0600); err != nil {
			return fmt.Errorf("failed to write proxy-ca.pem: %s", err)
		}
		fmt.Printf("proxy serving certificate already minted in %s/%s\n", namespace, name)

		return nil
	}
	if !apierrors.IsNotFound(err) {
		return fmt.Errorf("failed to read secret %s/%s: %s", namespace, name, err)
	}

	host := fmt.Sprintf("%s.%s.svc.cluster.local", service, namespace)
	bundle, err := util.NewTLSSelfSignedCertKey(host, []net.IP{net.ParseIP("127.0.0.1")}, nil)
	if err != nil {
		return fmt.Errorf("failed to generate a serving certificate for %q: %s", host, err)
	}

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
		Type:       corev1.SecretTypeTLS,
		Data: map[string][]byte{
			corev1.TLSCertKey:       bundle.CertBytes,
			corev1.TLSPrivateKeyKey: bundle.KeyBytes,
		},
	}
	if _, err := client.CoreV1().Secrets(namespace).Create(ctx, secret, metav1.CreateOptions{}); err != nil {
		return fmt.Errorf("failed to create secret %s/%s: %s", namespace, name, err)
	}

	if err := os.WriteFile(filepath.Join(state, "proxy-ca.pem"), bundle.CertBytes, 0600); err != nil {
		return fmt.Errorf("failed to write proxy-ca.pem: %s", err)
	}

	fmt.Printf("proxy serving certificate minted for %s and 127.0.0.1 in %s/%s\n", host, namespace, name)

	return nil
}

// servingCertFromSecret returns the serving certificate a kubernetes.io/tls
// Secret carries, refusing any other type and an absent or empty tls.crt so a
// malformed Secret fails here instead of producing an empty proxy-ca.pem.
func servingCertFromSecret(secret *corev1.Secret) ([]byte, error) {
	if secret.Type != corev1.SecretTypeTLS {
		return nil, fmt.Errorf("type %s, want %s", secret.Type, corev1.SecretTypeTLS)
	}
	cert := secret.Data[corev1.TLSCertKey]
	if len(cert) == 0 {
		return nil, fmt.Errorf("no %s data", corev1.TLSCertKey)
	}

	return cert, nil
}
