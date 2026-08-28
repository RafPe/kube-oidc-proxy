// Copyright Jetstack Ltd. See LICENSE for details.
package versions

import (
	"os"
	"regexp"
	"strings"
	"testing"

	"golang.org/x/mod/modfile"
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

// The newest declared minor must equal the k8s.io/api minor in go.mod: the
// library dependency is the real upper bound of what this code supports, so a
// dependency bump can never silently outrun the tested window.
func TestNewestMinorMatchesGoMod(t *testing.T) {
	data, err := os.ReadFile("../../../go.mod")
	if err != nil {
		t.Fatalf("read go.mod: %v", err)
	}
	mf, err := modfile.Parse("go.mod", data, nil)
	if err != nil {
		t.Fatalf("parse go.mod: %v", err)
	}
	var apiVer string
	for _, r := range mf.Require {
		if r.Mod.Path == "k8s.io/api" {
			apiVer = r.Mod.Version
		}
	}
	if apiVer == "" {
		t.Fatal("k8s.io/api not found in go.mod")
	}
	goModMinor := strings.Split(strings.TrimPrefix(apiVer, "v0."), ".")[0]
	latestMinor := strings.Split(Latest(), ".")[1]
	if goModMinor != latestMinor {
		t.Fatalf("go.mod k8s.io/api is v0.%s but newest manifest minor is 1.%s -- bump the manifest (and verify compatibility) together with the k8s.io libraries", goModMinor, latestMinor)
	}
}
