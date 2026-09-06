// Copyright Jetstack Ltd. See LICENSE for details.

// Command issuer deploys the e2e suite's mock OIDC issuer into the metrics
// demo cluster and writes the key material the load generator signs tokens
// with. It reuses helper.DeployIssuer rather than reimplementing the
// Deployment, so the demo authenticates against exactly the issuer the e2e
// suite does.
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/rafpe/kube-oidc-proxy/test/e2e/framework/config"
	"github.com/rafpe/kube-oidc-proxy/test/e2e/framework/helper"
)

func main() {
	state := flag.String("state", "hack/metrics-demo/.state", "directory holding the demo's kubeconfig and generated key material")
	namespace := flag.String("namespace", "proxy", "namespace to deploy the issuer into")
	flag.Parse()

	if err := run(*state, *namespace); err != nil {
		log.Fatalf("deploy issuer: %s", err)
	}
}

func run(state, namespace string) error {
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

	return nil
}
