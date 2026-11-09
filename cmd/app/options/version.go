// Copyright Jetstack Ltd. See LICENSE for details.
package options

import (
	"fmt"
	"io"
	"runtime"
	"runtime/debug"

	"github.com/spf13/pflag"
	apimachineryversion "k8s.io/apimachinery/pkg/version"
	cliflag "k8s.io/component-base/cli/flag"
)

// VersionOptions owns the --version flag and reports the build information
// of this binary.
type VersionOptions struct {
	requested bool
	build     buildInfo
}

// Build information, stamped at link time by hack/lib/version.sh through
// -X cmd/app/options.<name>; renaming one silently drops its stamp. -X only
// replaces a variable initialized to a constant, so the defaults stay
// literals and the fallback for an unstamped build lives in resolveBuild.
var (
	gitMajor     string // major version, always numeric
	gitMinor     string // minor version, numeric possibly followed by "+"
	gitVersion   = unstampedVersion
	gitCommit    = unstampedCommit // sha1 from git, output of $(git rev-parse HEAD)
	gitTreeState string            // state of git tree, either "clean" or "dirty"

	buildDate = "1970-01-01T00:00:00Z" // build date in ISO8601 format, output of $(date -u +'%Y-%m-%dT%H:%M:%SZ')
)

// The values an unstamped build (plain go build, go test) starts from.
const (
	unstampedVersion = "v0.0.0-dev"
	unstampedCommit  = "unknown"
)

// buildInfo is the version, commit and tree state this binary reports.
type buildInfo struct {
	version   string
	commit    string
	treeState string
}

// resolveBuild returns the stamped build information, filling what was not
// stamped from what the go command recorded in bi: the module version, which
// go build derives from the VCS, and the vcs.revision and vcs.modified
// settings. bi may be nil; anything still unknown keeps its unstamped
// default.
func resolveBuild(stamped buildInfo, bi *debug.BuildInfo) buildInfo {
	b := stamped
	if bi == nil {
		return b
	}
	if b.version == unstampedVersion && bi.Main.Version != "" && bi.Main.Version != "(devel)" {
		b.version = bi.Main.Version
	}
	if b.commit != unstampedCommit {
		return b
	}
	for _, s := range bi.Settings {
		switch s.Key {
		case "vcs.revision":
			b.commit = s.Value
		case "vcs.modified":
			if b.treeState == "" {
				b.treeState = map[string]string{"true": "dirty", "false": "clean"}[s.Value]
			}
		}
	}
	return b
}

// NewVersionOptions registers the Version flag set on nfs and returns the
// options that report the build information of this binary.
func NewVersionOptions(nfs *cliflag.NamedFlagSets) *VersionOptions {
	bi, _ := debug.ReadBuildInfo()
	v := &VersionOptions{
		build: resolveBuild(buildInfo{version: gitVersion, commit: gitCommit, treeState: gitTreeState}, bi),
	}
	return v.AddFlags(nfs.FlagSet("Version"))
}

// AddFlags binds --version to fs and returns v for chaining.
func (v *VersionOptions) AddFlags(fs *pflag.FlagSet) *VersionOptions {
	fs.BoolVar(&v.requested, "version", false, "Print version information and quit")
	return v
}

// Requested reports whether --version was given on the command line.
func (v *VersionOptions) Requested() bool {
	return v.requested
}

// Version returns the build version this binary reports, for the startup
// record that fixes what an operator is actually running.
func (v *VersionOptions) Version() string {
	return v.build.version
}

// Commit returns the git commit this binary was built from, for the build
// information the metrics endpoint reports.
func (v *VersionOptions) Commit() string {
	return v.build.commit
}

// PrintVersion writes the build information to w. It is the --version flag's
// whole job, so the command calls it before anything else is validated or
// built, and then returns without starting; main owns the exit status.
func (v *VersionOptions) PrintVersion(w io.Writer) {
	_, _ = fmt.Fprintf(w, "%s version: %#v\n", AppName,
		apimachineryversion.Info{
			Major:        gitMajor,
			Minor:        gitMinor,
			GitVersion:   v.build.version,
			GitCommit:    v.build.commit,
			GitTreeState: v.build.treeState,
			BuildDate:    buildDate,
			GoVersion:    runtime.Version(),
			Compiler:     runtime.Compiler,
			Platform:     fmt.Sprintf("%s/%s", runtime.GOOS, runtime.GOARCH),
		},
	)
}
