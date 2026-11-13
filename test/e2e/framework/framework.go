// Copyright Jetstack Ltd. See LICENSE for details.
package framework

import (
	"context"
	"fmt"
	"net/url"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/rafpe/kube-oidc-proxy/test/e2e/framework/config"
	"github.com/rafpe/kube-oidc-proxy/test/e2e/framework/helper"
	"github.com/rafpe/kube-oidc-proxy/test/kind"
	"github.com/rafpe/kube-oidc-proxy/test/util/idtoken"
	"github.com/rafpe/kube-oidc-proxy/test/util/keybundle"
)

// defaultConfig is the configuration the default frameworks run against. It is
// nil until SetDefaultConfig is called, which happens during
// SynchronizedBeforeSuite, after every framework has already been constructed
// at tree-construction time. Frameworks therefore resolve it lazily, in their
// setup node, rather than capturing it when they are built.
var defaultConfig *config.Config

// SetDefaultConfig validates c and makes it the configuration every default
// framework runs against. The suite calls it once per Ginkgo process, from the
// second function of SynchronizedBeforeSuite; it must not be called from a spec.
func SetDefaultConfig(c config.Config) error {
	if err := c.Validate(); err != nil {
		return fmt.Errorf("validating e2e config: %w", err)
	}
	defaultConfig = &c
	return nil
}

// requireDefaultConfig returns the configuration set by SetDefaultConfig,
// failing the current node if the suite never set it.
func requireDefaultConfig() *config.Config {
	if defaultConfig == nil {
		Fail("framework.SetDefaultConfig was not called; it must run in SynchronizedBeforeSuite before any framework setup")
	}
	return defaultConfig
}

type Framework struct {
	BaseName string

	KubeClientSet kubernetes.Interface
	ProxyClient   kubernetes.Interface

	Namespace *corev1.Namespace

	// BeforeProxyDeploy, if set, runs after the primary issuer is deployed and
	// before the proxy is deployed. Tests use it to stage resources the proxy
	// needs at startup (e.g. an AuthenticationConfiguration ConfigMap) and to
	// populate ExtraProxyVolumes / ExtraProxyArgs. Avoids a delete-redeploy
	// cycle for tests that need non-default proxy flags.
	BeforeProxyDeploy func(ctx context.Context)
	ExtraProxyVolumes []corev1.Volume
	ExtraProxyArgs    []string
	// ExtraProxyExtras, if set, adds volumes, mounts, sidecars and ports to
	// the proxy pod the framework deploys.
	ExtraProxyExtras *helper.ProxyExtras

	// config is nil for default frameworks until their setup node resolves it
	// through requireDefaultConfig.
	config *config.Config
	helper *helper.Helper

	issuerKeyBundle, proxyKeyBundle *keybundle.Bundle
	issuerURL, proxyURL             *url.URL
}

// NewDefaultFramework is NewFramework using the configuration set by
// SetDefaultConfig, read when the first spec's setup runs.
func NewDefaultFramework(baseName string) *Framework {
	return NewFramework(baseName, nil)
}

func NewFramework(baseName string, config *config.Config) *Framework {
	f := newFramework(baseName, config)

	JustBeforeEach(f.BeforeEach)
	AfterEach(f.AfterEach)

	return f
}

// NewOrderedDefaultFramework is NewOrderedFramework using the configuration set
// by SetDefaultConfig, read when the container's setup runs.
func NewOrderedDefaultFramework(baseName string) *Framework {
	return NewOrderedFramework(baseName, nil)
}

// NewOrderedFramework deploys the namespace, issuer and proxy once for the
// whole enclosing container rather than once per spec, so a run of specs
// sharing the same proxy configuration pays for a single deploy. It must be
// called inside an Ordered container — Ginkgo panics at tree construction
// otherwise — and only for specs that share a configuration and leave no
// residue that a sibling spec depends on being absent.
//
// Proxy logs are still gathered after every spec; only the teardown of the
// proxy, issuer and namespace is deferred to the end of the container.
func NewOrderedFramework(baseName string, config *config.Config) *Framework {
	f := newFramework(baseName, config)

	BeforeAll(f.BeforeEach)
	AfterEach(f.gatherProxyLogs)
	AfterAll(f.deleteResources)

	return f
}

func newFramework(baseName string, config *config.Config) *Framework {
	return &Framework{
		BaseName: baseName,
		config:   config,
	}
}

// BeforeEach deploys the namespace, issuer and proxy the specs run against.
// It runs as a setup node, so ctx is that node's: cancelled when the node ends
// or the suite is interrupted, and never kept beyond it.
func (f *Framework) BeforeEach(ctx context.Context) {
	if f.config == nil {
		f.config = requireDefaultConfig()
	}
	f.helper = helper.NewHelper(f.config)

	By("Creating a kubernetes client")

	config, err := clientcmd.BuildConfigFromFlags("", f.config.KubeConfigPath)
	Expect(err).NotTo(HaveOccurred())

	f.KubeClientSet, err = kubernetes.NewForConfig(config)
	Expect(err).NotTo(HaveOccurred())

	By("Building a namespace api object")
	f.Namespace, err = f.CreateKubeNamespace(ctx, f.BaseName)
	Expect(err).NotTo(HaveOccurred())

	By("Using the namespace " + f.Namespace.Name)

	f.helper.KubeClient = f.KubeClientSet

	By("Deploying mock OIDC Issuer")
	issuerKeyBundle, issuerURL, err := f.helper.DeployIssuer(ctx, f.Namespace.Name)
	Expect(err).NotTo(HaveOccurred())

	f.issuerURL, f.issuerKeyBundle = issuerURL, issuerKeyBundle

	if f.BeforeProxyDeploy != nil {
		f.BeforeProxyDeploy(ctx)
	}

	By("Deploying kube-oidc-proxy")
	proxyKeyBundle, proxyURL, err := f.helper.DeployProxyWithExtras(ctx, f.Namespace,
		issuerURL, clientID, issuerKeyBundle, f.ExtraProxyVolumes, f.ExtraProxyExtras, f.ExtraProxyArgs...)
	Expect(err).NotTo(HaveOccurred())

	f.proxyURL, f.proxyKeyBundle = proxyURL, proxyKeyBundle

	By("Creating Proxy Client")
	f.ProxyClient = f.NewProxyClient()
}

// AfterEach deletes the namespace, after reading its events.
func (f *Framework) AfterEach(ctx context.Context) {
	f.gatherProxyLogs()
	f.deleteResources(ctx)
}

// gatherProxyLogs dumps the proxy logs to the test output. It runs after every
// spec, including in Ordered containers where teardown is deferred, so a
// failing spec always has the logs of the proxy it ran against.
func (f *Framework) gatherProxyLogs() {
	// --all-containers keeps this working when the proxy pod has a sidecar, as
	// the audit to file case does.
	err := f.Helper().Kubectl(f.Namespace.Name).Run("logs", "--all-containers", "-lapp=kube-oidc-proxy-e2e")
	if err != nil {
		By("Failed to gather logs from kube-oidc-proxy: " + err.Error())
	}
}

func (f *Framework) deleteResources(ctx context.Context) {
	By("Deleting kube-oidc-proxy deployment")
	err := f.Helper().DeleteProxy(ctx, f.Namespace.Name)
	Expect(err).NotTo(HaveOccurred())

	By("Deleting mock OIDC issuer")
	err = f.Helper().DeleteIssuer(ctx, f.Namespace.Name)
	Expect(err).NotTo(HaveOccurred())

	By("Deleting test namespace")
	err = f.DeleteKubeNamespace(ctx, f.Namespace.Name)
	Expect(err).NotTo(HaveOccurred())
}

func (f *Framework) DeployProxyWith(ctx context.Context, extraVolumes []corev1.Volume, extraArgs ...string) {
	f.DeployProxyWithExtras(ctx, extraVolumes, nil, extraArgs...)
}

// DeployProxyWithExtras redeploys the proxy with extra volumes, plus writable
// volumes and sidecar containers that extraVolumes cannot express.
func (f *Framework) DeployProxyWithExtras(ctx context.Context, extraVolumes []corev1.Volume, extras *helper.ProxyExtras, extraArgs ...string) {
	By("Deleting kube-oidc-proxy deployment")
	err := f.Helper().DeleteProxy(ctx, f.Namespace.Name)
	Expect(err).NotTo(HaveOccurred())

	err = f.Helper().WaitForDeploymentToDelete(ctx, f.Namespace.Name, kind.ProxyImageName, time.Second*30)
	Expect(err).NotTo(HaveOccurred())

	By(fmt.Sprintf("Deploying kube-oidc-proxy with extra args %s", extraArgs))
	f.proxyKeyBundle, f.proxyURL, err = f.helper.DeployProxyWithExtras(ctx, f.Namespace, f.issuerURL,
		clientID, f.issuerKeyBundle, extraVolumes, extras, extraArgs...)
	Expect(err).NotTo(HaveOccurred())
}

func (f *Framework) Helper() *helper.Helper {
	return f.helper
}

func (f *Framework) IssuerKeyBundle() *keybundle.Bundle {
	return f.issuerKeyBundle
}

func (f *Framework) ProxyKeyBundle() *keybundle.Bundle {
	return f.proxyKeyBundle
}

func (f *Framework) IssuerURL() *url.URL {
	return f.issuerURL
}

func (f *Framework) ProxyURL() *url.URL {
	return f.proxyURL
}

func (f *Framework) ClientID() string {
	return clientID
}

// SignedTokenFor mints a token for the given identity, signed by the suite's
// mock issuer and valid for ten minutes, so the proxy's OIDC authenticator
// accepts it.
func (f *Framework) SignedTokenFor(username string, groups []string) string {
	payload := idtoken.NewPayloadForIdentity(f.issuerURL, clientID,
		username, groups, time.Now().Add(10*time.Minute))

	signed, err := idtoken.Sign(f.issuerKeyBundle, payload)
	Expect(err).NotTo(HaveOccurred())
	return signed
}

// SignedToken is SignedTokenFor the suite's standard identity, the one the
// cases bind RBAC to and NewProxyRestConfig authenticates as.
func (f *Framework) SignedToken() string {
	return f.SignedTokenFor(idtoken.DefaultUsername, idtoken.DefaultGroups())
}

// NewProxyRestConfig returns a client-go configuration that reaches the proxy
// as the suite's standard identity, with a freshly signed token.
func (f *Framework) NewProxyRestConfig() *rest.Config {
	config, err := f.Helper().NewValidRestConfig(f.proxyKeyBundle, f.proxyURL, f.SignedToken())
	Expect(err).NotTo(HaveOccurred())

	return config
}

func (f *Framework) NewProxyClient() kubernetes.Interface {
	proxyConfig := f.NewProxyRestConfig()

	proxyClient, err := kubernetes.NewForConfig(proxyConfig)
	Expect(err).NotTo(HaveOccurred())

	return proxyClient
}

// CasesDescribe declares a test case container. args is the container body
// plus any Ginkgo decorators, such as Ordered and ContinueOnFailure for cases
// that share a single deploy across their specs.
func CasesDescribe(text string, args ...any) bool {
	return Describe("[TEST] "+text, args...)
}
