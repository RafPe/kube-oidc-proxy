// Copyright Jetstack Ltd. See LICENSE for details.
package options

import (
	"fmt"
	"os"
	"runtime"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	apimachineryversion "k8s.io/apimachinery/pkg/version"
	cliflag "k8s.io/component-base/cli/flag"
)

// VersionOptions carries the build information stamped into the binary and
// owns the --version flag that prints it.
type VersionOptions struct {
	gitMajor     string // major version, always numeric
	gitMinor     string // minor version, numeric possibly followed by "+"
	gitVersion   string
	gitCommit    string // sha1 from git, output of $(git rev-parse HEAD)
	gitTreeState string // state of git tree, either "clean" or "dirty"

	buildDate string // build date in ISO8601 format, output of $(date -u +'%Y-%m-%dT%H:%M:%SZ')
}

var (
	gitMajor     string // major version, always numeric
	gitMinor     string // minor version, numeric possibly followed by "+"
	gitVersion   = "v0.0.0-master+$Format:%h$"
	gitCommit    = "$Format:%H$" // sha1 from git, output of $(git rev-parse HEAD)
	gitTreeState = ""            // state of git tree, either "clean" or "dirty"

	buildDate = "1970-01-01T00:00:00Z" // build date in ISO8601 format, output of $(date -u +'%Y-%m-%dT%H:%M:%SZ')
)

// NewVersionOptions registers the Version flag set on nfs and returns the
// options carrying the build information stamped into the binary.
func NewVersionOptions(nfs *cliflag.NamedFlagSets) *VersionOptions {
	m := &VersionOptions{
		gitMajor:     gitMajor,
		gitMinor:     gitMinor,
		gitVersion:   gitVersion,
		gitCommit:    gitCommit,
		gitTreeState: gitTreeState,
		buildDate:    buildDate,
	}

	return m.AddFlags(nfs.FlagSet("Version"))
}

// AddFlags binds --version to fs and returns m for chaining.
func (m *VersionOptions) AddFlags(fs *pflag.FlagSet) *VersionOptions {
	fs.Bool("version", false, "Print version information and quit")
	return m
}

// Requested reports whether --version was given on the command line.
func (m *VersionOptions) Requested(cmd *cobra.Command) bool {
	return cmd.Flag("version").Value.String() == "true"
}

// Version returns the build version this binary reports, for the startup
// record that fixes what an operator is actually running.
func (m *VersionOptions) Version() string {
	return m.gitVersion
}

// Commit returns the git commit this binary was built from, for the build
// information the metrics endpoint reports.
func (m *VersionOptions) Commit() string {
	return m.gitCommit
}

// PrintVersionAndExit prints the build information and ends the process. It
// is the --version flag's whole job, so the command calls it before anything
// else is validated or built.
func (m *VersionOptions) PrintVersionAndExit() {
	fmt.Printf("%s version: %#v\n", AppName,
		apimachineryversion.Info{
			Major:        m.gitMajor,
			Minor:        m.gitMinor,
			GitVersion:   m.gitVersion,
			GitCommit:    m.gitCommit,
			GitTreeState: m.gitTreeState,
			BuildDate:    m.buildDate,
			GoVersion:    runtime.Version(),
			Compiler:     runtime.Compiler,
			Platform:     fmt.Sprintf("%s/%s", runtime.GOOS, runtime.GOARCH),
		},
	)

	os.Exit(0)
}
