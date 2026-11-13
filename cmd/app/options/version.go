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

// VersionOptions owns the --version flag and reports the build information
// stamped into the binary. It holds no copy of that information: the package
// variables below are the single source, read directly.
type VersionOptions struct{}

// Build information, stamped at link time by hack/lib/version.sh through
// -X cmd/app/options.<name>; renaming one silently drops its stamp.
var (
	gitMajor     string // major version, always numeric
	gitMinor     string // minor version, numeric possibly followed by "+"
	gitVersion   = "v0.0.0-master+$Format:%h$"
	gitCommit    = "$Format:%H$" // sha1 from git, output of $(git rev-parse HEAD)
	gitTreeState = ""            // state of git tree, either "clean" or "dirty"

	buildDate = "1970-01-01T00:00:00Z" // build date in ISO8601 format, output of $(date -u +'%Y-%m-%dT%H:%M:%SZ')
)

// NewVersionOptions registers the Version flag set on nfs and returns the
// options that report the build information stamped into the binary.
func NewVersionOptions(nfs *cliflag.NamedFlagSets) *VersionOptions {
	v := &VersionOptions{}
	return v.AddFlags(nfs.FlagSet("Version"))
}

// AddFlags binds --version to fs and returns v for chaining.
func (v *VersionOptions) AddFlags(fs *pflag.FlagSet) *VersionOptions {
	fs.Bool("version", false, "Print version information and quit")
	return v
}

// Requested reports whether --version was given on the command line.
func (v *VersionOptions) Requested(cmd *cobra.Command) bool {
	return cmd.Flag("version").Value.String() == "true"
}

// Version returns the build version this binary reports, for the startup
// record that fixes what an operator is actually running.
func (v *VersionOptions) Version() string {
	return gitVersion
}

// Commit returns the git commit this binary was built from, for the build
// information the metrics endpoint reports.
func (v *VersionOptions) Commit() string {
	return gitCommit
}

// PrintVersionAndExit prints the build information and ends the process. It
// is the --version flag's whole job, so the command calls it before anything
// else is validated or built.
func (v *VersionOptions) PrintVersionAndExit() {
	fmt.Printf("%s version: %#v\n", AppName,
		apimachineryversion.Info{
			Major:        gitMajor,
			Minor:        gitMinor,
			GitVersion:   gitVersion,
			GitCommit:    gitCommit,
			GitTreeState: gitTreeState,
			BuildDate:    buildDate,
			GoVersion:    runtime.Version(),
			Compiler:     runtime.Compiler,
			Platform:     fmt.Sprintf("%s/%s", runtime.GOOS, runtime.GOARCH),
		},
	)

	os.Exit(0)
}
