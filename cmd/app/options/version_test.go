// Copyright Jetstack Ltd. See LICENSE for details.
package options

import (
	"runtime/debug"
	"testing"

	"github.com/spf13/cobra"
)

// TestVersionOptionsReportBuildInformation pins that --version is detected
// without being acted on by the options themselves, and that an unstamped
// binary (as this test binary is) reports its unstamped defaults rather than
// an empty or placeholder value.
func TestVersionOptionsReportBuildInformation(t *testing.T) {
	o := New()
	cmd := &cobra.Command{Use: "test"}
	o.AddFlags(cmd)

	if o.Version.Version() != unstampedVersion || o.Version.Commit() != unstampedCommit {
		t.Fatalf("Version()/Commit() = %q/%q, want %q/%q", o.Version.Version(), o.Version.Commit(), unstampedVersion, unstampedCommit)
	}

	if err := cmd.ParseFlags(nil); err != nil {
		t.Fatal(err)
	}
	if o.Version.Requested() {
		t.Fatal("--version reported as requested without the flag")
	}
	if err := cmd.ParseFlags([]string{"--version"}); err != nil {
		t.Fatal(err)
	}
	if !o.Version.Requested() {
		t.Fatal("--version was given but not reported as requested")
	}
	// Validate must stay a pure validator: --version is the command's to act on.
	if err := o.Validate(cmd); err != nil {
		t.Fatalf("Validate() with --version = %v, want nil", err)
	}
}

// TestResolveBuild pins how an unstamped build fills its version information
// from what the go command recorded, and that a stamp always wins.
func TestResolveBuild(t *testing.T) {
	unstamped := buildInfo{version: unstampedVersion, commit: unstampedCommit}
	vcs := &debug.BuildInfo{
		Main: debug.Module{Version: "v1.2.3-0.20260101000000-0123456789ab+dirty"},
		Settings: []debug.BuildSetting{
			{Key: "vcs.revision", Value: "0123456789abcdef0123456789abcdef01234567"},
			{Key: "vcs.modified", Value: "true"},
		},
	}

	tests := map[string]struct {
		stamped buildInfo
		bi      *debug.BuildInfo
		want    buildInfo
	}{
		"no build info keeps the unstamped defaults": {
			stamped: unstamped,
			want:    unstamped,
		},
		"a devel build without VCS information keeps the defaults": {
			stamped: unstamped,
			bi:      &debug.BuildInfo{Main: debug.Module{Version: "(devel)"}},
			want:    unstamped,
		},
		"an unstamped build reports what the go command recorded": {
			stamped: unstamped,
			bi:      vcs,
			want: buildInfo{
				version:   "v1.2.3-0.20260101000000-0123456789ab+dirty",
				commit:    "0123456789abcdef0123456789abcdef01234567",
				treeState: "dirty",
			},
		},
		"a clean checkout is reported clean": {
			stamped: unstamped,
			bi: &debug.BuildInfo{Settings: []debug.BuildSetting{
				{Key: "vcs.revision", Value: "abc"},
				{Key: "vcs.modified", Value: "false"},
			}},
			want: buildInfo{version: unstampedVersion, commit: "abc", treeState: "clean"},
		},
		"stamped values win over the build info": {
			stamped: buildInfo{version: "v1.0.0", commit: "stamped", treeState: "clean"},
			bi:      vcs,
			want:    buildInfo{version: "v1.0.0", commit: "stamped", treeState: "clean"},
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			if got := resolveBuild(tc.stamped, tc.bi); got != tc.want {
				t.Errorf("resolveBuild() = %+v, want %+v", got, tc.want)
			}
		})
	}
}
