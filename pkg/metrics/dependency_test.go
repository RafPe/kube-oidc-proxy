// Copyright Jetstack Ltd. See LICENSE for details.
package metrics

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"golang.org/x/mod/modfile"
	"golang.org/x/mod/semver"
)

// TestClientGolangVersionFloor pins the metrics library at or above the
// release that fixes the promhttp nil-URL panic, and pins it as a direct
// requirement. It reads the requirement from go.mod, so it is RED at an
// indirect 1.24.0 and GREEN once go.mod requires 1.24.1 directly.
//
// The module graph is read from go.mod rather than from
// debug.ReadBuildInfo(): a binary built by "go test" carries no dependency
// list at all (Main.Version is "(devel)" and Deps is empty), so build
// information cannot report the version under test.
func TestClientGolangVersionFloor(t *testing.T) {
	const module, floor = "github.com/prometheus/client_golang", "v1.24.1"

	path := findGoMod(t)
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	f, err := modfile.Parse(path, b, nil)
	if err != nil {
		t.Fatalf("parsing %s: %v", path, err)
	}

	for _, req := range f.Require {
		if req.Mod.Path != module {
			continue
		}
		if semver.Compare(req.Mod.Version, floor) < 0 {
			t.Fatalf("%s is %s, want at least %s", module, req.Mod.Version, floor)
		}
		if req.Indirect {
			t.Fatalf("%s must be a direct requirement", module)
		}
		reg := prometheus.NewRegistry()
		if promhttp.HandlerFor(reg, promhttp.HandlerOpts{}) == nil {
			t.Fatal("promhttp.HandlerFor returned nil")
		}
		return
	}
	t.Fatalf("%s is not required by %s", module, path)
}

// findGoMod returns the path of the module's go.mod, walking up from the
// test's working directory.
func findGoMod(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getting the working directory: %v", err)
	}
	for {
		path := filepath.Join(dir, "go.mod")
		// A Stat failure other than "no such file" is a broken filesystem or a
		// permission problem, not a directory to walk past: report it rather
		// than climbing to the root and blaming a missing go.mod.
		_, err := os.Stat(path)
		switch {
		case err == nil:
			return path
		case !errors.Is(err, os.ErrNotExist):
			t.Fatalf("stat %s: %v", path, err)
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatalf("no go.mod at or above %s", dir)
		}
		dir = parent
	}
}
