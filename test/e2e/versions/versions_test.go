// Copyright Jetstack Ltd. See LICENSE for details.
package versions

import (
	"os"
	"regexp"
	"strings"
	"testing"

	"golang.org/x/mod/modfile"
	"golang.org/x/mod/module"
	"golang.org/x/mod/semver"
)

func TestManifestIsValid(t *testing.T) {
	sup := Supported()
	if len(sup) == 0 {
		t.Fatal("manifest declares no supported versions")
	}
	imageRe := regexp.MustCompile(`^kindest/node:v(\d+\.\d+\.\d+)@sha256:[0-9a-f]{64}$`)
	for i, e := range sup {
		m := imageRe.FindStringSubmatch(e.Image)
		if m == nil {
			t.Fatalf("entry %d: image %q is not a digest-pinned kindest/node reference", i, e.Image)
		}
		if m[1] != e.Version {
			t.Fatalf("entry %d: image tag %q does not match version %q", i, m[1], e.Version)
		}
		if i > 0 && semver.Compare("v"+sup[i-1].Version, "v"+e.Version) <= 0 {
			t.Fatalf("entries must be newest-first: %q is not newer than %q", sup[i-1].Version, e.Version)
		}
	}
	if Latest() != sup[0].Version {
		t.Fatalf("Latest() = %q, want first entry %q", Latest(), sup[0].Version)
	}
}

func TestImageFor(t *testing.T) {
	img, err := ImageFor(Latest())
	if err != nil {
		t.Fatalf("ImageFor(latest): %v", err)
	}
	if !strings.Contains(img, "@sha256:") {
		t.Fatalf("ImageFor(latest) = %q, want digest-pinned reference", img)
	}
	if _, err := ImageFor("1.2.3"); err == nil {
		t.Fatal("ImageFor(unknown) must fail loudly, got nil error")
	}
}

// readGoMod parses the repository's go.mod.
func readGoMod(t *testing.T) *modfile.File {
	t.Helper()
	data, err := os.ReadFile("../../../go.mod")
	if err != nil {
		t.Fatalf("read go.mod: %v", err)
	}
	mf, err := modfile.Parse("go.mod", data, nil)
	if err != nil {
		t.Fatalf("parse go.mod: %v", err)
	}
	return mf
}

// requiredVersion returns the version go.mod requires for path.
func requiredVersion(t *testing.T, mf *modfile.File, path string) string {
	t.Helper()
	for _, r := range mf.Require {
		if r.Mod.Path == path {
			return r.Mod.Version
		}
	}
	t.Fatalf("%s not found in go.mod", path)
	return ""
}

// The newest declared minor must equal the k8s.io/api minor in go.mod: the
// library dependency is the real upper bound of what this code supports, so a
// dependency bump can never silently outrun the tested window.
func TestNewestMinorMatchesGoMod(t *testing.T) {
	apiVer := requiredVersion(t, readGoMod(t), "k8s.io/api")
	goModMinor := strings.Split(strings.TrimPrefix(apiVer, "v0."), ".")[0]
	latestMinor := strings.Split(Latest(), ".")[1]
	if goModMinor != latestMinor {
		t.Fatalf("go.mod k8s.io/api is v0.%s but newest manifest minor is 1.%s -- bump the manifest (and verify compatibility) together with the k8s.io libraries", goModMinor, latestMinor)
	}
}

// Every k8s.io module published from the Kubernetes staging tree (versioned
// v0.<minor>.<patch>, direct or indirect) must be at exactly the k8s.io/api
// version: they are cut from one release and mixing them is unsupported, so a
// partial bump must fail here rather than at run time. Modules versioned on
// their own (k8s.io/klog/v2, and k8s.io/kube-openapi and k8s.io/utils, which
// only publish pseudo-versions) are not part of the set.
func TestKubernetesModulesInLockstep(t *testing.T) {
	mf := readGoMod(t)
	want := requiredVersion(t, mf, "k8s.io/api")

	var checked int
	for _, r := range mf.Require {
		path, ver := r.Mod.Path, r.Mod.Version
		if !strings.HasPrefix(path, "k8s.io/") || semver.Major(ver) != "v0" || module.IsPseudoVersion(ver) {
			continue
		}
		checked++
		if ver != want {
			t.Errorf("%s is %s but k8s.io/api is %s -- the k8s.io libraries must move in lockstep", path, ver, want)
		}
	}
	for _, r := range mf.Replace {
		if strings.HasPrefix(r.Old.Path, "k8s.io/") {
			t.Errorf("go.mod replaces %s, which takes it out of the lockstep this test checks", r.Old.Path)
		}
	}
	// k8s.io/api itself plus at least client-go and apimachinery: fewer means
	// the filter above stopped matching what it is meant to.
	if checked < 3 {
		t.Fatalf("only %d k8s.io staging modules matched; the lockstep filter is broken", checked)
	}
}
