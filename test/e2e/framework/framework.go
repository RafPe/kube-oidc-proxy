// Copyright Jetstack Ltd. See LICENSE for details.
package framework

import (
	"fmt"
	"net/url"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/cli-runtime/pkg/genericclioptions"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"github.com/rafpe/kube-oidc-proxy/test/e2e/framework/config"
	"github.com/rafpe/kube-oidc-proxy/test/e2e/framework/helper"
	"github.com/rafpe/kube-oidc-proxy/test/kind"
	"github.com/rafpe/kube-oidc-proxy/test/util"
)

var DefaultConfig = &config.Config{}

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
	BeforeProxyDeploy func()
	ExtraProxyVolumes []corev1.Volume
	ExtraProxyArgs    []string

	config *config.Config
	helper *helper.Helper

	issuerKeyBundle, proxyKeyBundle *util.KeyBundle
	issuerURL, proxyURL             *url.URL
}

func NewDefaultFramework(baseName string) *Framework {
	return NewFramework(baseName, DefaultConfig)
}

func NewFramework(baseName string, config *config.Config) *Framework {
	f := newFramework(baseName, config)

	JustBeforeEach(f.BeforeEach)
	AfterEach(f.AfterEach)

	return f
}

// NewOrderedDefaultFramework is NewOrderedFramework using DefaultConfig.
func NewOrderedDefaultFramework(baseName string) *Framework {
	return NewOrderedFramework(baseName, DefaultConfig)
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

func (f *Framework) BeforeEach() {
	f.helper = helper.NewHelper(f.config)

	By("Creating a kubernetes client")

	clientConfigFlags := genericclioptions.NewConfigFlags(true)
	clientConfigFlags.KubeConfig = &f.config.KubeConfigPath
	config, err := clientConfigFlags.ToRESTConfig()
	Expect(err).NotTo(HaveOccurred())

	f.KubeClientSet, err = kubernetes.NewForConfig(config)
	Expect(err).NotTo(HaveOccurred())

	By("Building a namespace api object")
	f.Namespace, err = f.CreateKubeNamespace(f.BaseName)
	Expect(err).NotTo(HaveOccurred())

	By("Using the namespace " + f.Namespace.Name)

	f.helper.KubeClient = f.KubeClientSet

	By("Deploying mock OIDC Issuer")
	issuerKeyBundle, issuerURL, err := f.helper.DeployIssuer(f.Namespace.Name)
	Expect(err).NotTo(HaveOccurred())

	f.issuerURL, f.issuerKeyBundle = issuerURL, issuerKeyBundle

	if f.BeforeProxyDeploy != nil {
		f.BeforeProxyDeploy()
	}

	By("Deploying kube-oidc-proxy")
	proxyKeyBundle, proxyURL, err := f.helper.DeployProxy(f.Namespace,
		issuerURL, clientID, issuerKeyBundle, f.ExtraProxyVolumes, f.ExtraProxyArgs...)
	Expect(err).NotTo(HaveOccurred())

	f.proxyURL, f.proxyKeyBundle = proxyURL, proxyKeyBundle

	By("Creating Proxy Client")
	f.ProxyClient = f.NewProxyClient()
}

// AfterEach deletes the namespace, after reading its events.
func (f *Framework) AfterEach() {
	f.gatherProxyLogs()
	f.deleteResources()
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

func (f *Framework) deleteResources() {
	By("Deleting kube-oidc-proxy deployment")
	err := f.Helper().DeleteProxy(f.Namespace.Name)
	Expect(err).NotTo(HaveOccurred())

	By("Deleting mock OIDC issuer")
	err = f.Helper().DeleteIssuer(f.Namespace.Name)
	Expect(err).NotTo(HaveOccurred())

	By("Deleting test namespace")
	err = f.DeleteKubeNamespace(f.Namespace.Name)
	Expect(err).NotTo(HaveOccurred())
}

func (f *Framework) DeployProxyWith(extraVolumes []corev1.Volume, extraArgs ...string) {
	f.DeployProxyWithExtras(extraVolumes, nil, extraArgs...)
}

// DeployProxyWithExtras redeploys the proxy with extra volumes, plus writable
// volumes and sidecar containers that extraVolumes cannot express.
func (f *Framework) DeployProxyWithExtras(extraVolumes []corev1.Volume, extras *helper.ProxyExtras, extraArgs ...string) {
	By("Deleting kube-oidc-proxy deployment")
	err := f.Helper().DeleteProxy(f.Namespace.Name)
	Expect(err).NotTo(HaveOccurred())

	err = f.Helper().WaitForDeploymentToDelete(f.Namespace.Name, kind.ProxyImageName, time.Second*30)
	Expect(err).NotTo(HaveOccurred())

	By(fmt.Sprintf("Deploying kube-oidc-proxy with extra args %s", extraArgs))
	f.proxyKeyBundle, f.proxyURL, err = f.helper.DeployProxyWithExtras(f.Namespace, f.issuerURL,
		clientID, f.issuerKeyBundle, extraVolumes, extras, extraArgs...)
	Expect(err).NotTo(HaveOccurred())
}

func (f *Framework) Helper() *helper.Helper {
	return f.helper
}

func (f *Framework) IssuerKeyBundle() *util.KeyBundle {
	return f.issuerKeyBundle
}

func (f *Framework) ProxyKeyBundle() *util.KeyBundle {
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

func (f *Framework) NewProxyRestConfig() *rest.Config {
	config, err := f.Helper().NewValidRestConfig(f.issuerKeyBundle, f.proxyKeyBundle,
		f.issuerURL, f.proxyURL, clientID)
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
func CasesDescribe(text string, args ...interface{}) bool {
	return Describe("[TEST] "+text, args...)
}
