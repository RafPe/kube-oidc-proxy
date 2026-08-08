// Copyright Jetstack Ltd. See LICENSE for details.
package suite

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/ginkgo/v2/reporters"
	"github.com/onsi/gomega"
	"k8s.io/apimachinery/pkg/util/wait"

	_ "github.com/rafpe/kube-oidc-proxy/test/e2e/suite/cases"
)

func init() {
	wait.ForeverTestTimeout = time.Second * 60
}

func TestE2E(t *testing.T) {
	gomega.RegisterFailHandler(ginkgo.Fail)

	suiteConfig, reporterConfig := ginkgo.GinkgoConfiguration()
	// Turn on verbose by default to get spec names.
	reporterConfig.Verbose = true
	// Randomize specs as well as suites.
	suiteConfig.RandomizeAllSpecs = true

	ginkgo.RunSpecs(t, "kube-oidc-proxy e2e suite", suiteConfig, reporterConfig)
}

// ReportAfterSuite writes the JUnit report once every spec has run, replacing
// the v1 custom JUnit reporter wired through RunSpecsWithDefaultAndCustomReporters.
var _ = ginkgo.ReportAfterSuite("junit report", func(report ginkgo.Report) {
	junitPath := "../../../artifacts"
	if path := os.Getenv("ARTIFACTS"); path != "" {
		junitPath = path
	}

	if err := reporters.GenerateJUnitReport(report, filepath.Join(
		junitPath,
		"junit-go-e2e.xml",
	)); err != nil {
		ginkgo.GinkgoWriter.Printf("failed to generate JUnit report: %s\n", err)
	}
})
