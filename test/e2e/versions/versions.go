// Copyright Jetstack Ltd. See LICENSE for details.

// Package versions is the single source of truth for the Kubernetes versions
// this commit's e2e suite supports. The embedded manifest is also read by the
// test:e2e:versions job in .github/workflows/e2e.yaml, so local runs and CI
// cannot diverge. Bump procedure: MAINTAINING.md.
package versions

import (
	_ "embed"
	"encoding/json"
	"fmt"
)

//go:embed kubernetes-versions.json
var manifestJSON []byte

type Entry struct {
	Version string `json:"version"`
	Image   string `json:"image"`
}

type manifest struct {
	Kind      string  `json:"kind"`
	Supported []Entry `json:"supported"`
}

var m = func() manifest {
	var m manifest
	if err := json.Unmarshal(manifestJSON, &m); err != nil {
		panic(fmt.Sprintf("test/e2e/versions/kubernetes-versions.json is invalid: %v", err))
	}
	if len(m.Supported) == 0 {
		panic("test/e2e/versions/kubernetes-versions.json declares no supported versions")
	}
	return m
}()

// Supported returns the declared versions, newest first.
func Supported() []Entry { return m.Supported }

// Latest returns the newest declared version, the default for local runs and
// the only version the pull_request CI path tests.
func Latest() string { return m.Supported[0].Version }

// KindVersion returns the kind release the node images were built by.
func KindVersion() string { return m.Kind }

// ImageFor resolves a declared version to its digest-pinned node image. It
// fails loudly on undeclared versions: testing against an image the manifest
// does not vouch for would make "supported" meaningless.
func ImageFor(version string) (string, error) {
	for _, e := range m.Supported {
		if e.Version == version {
			return e.Image, nil
		}
	}
	return "", fmt.Errorf("kubernetes version %q is not declared in test/e2e/versions/kubernetes-versions.json (supported: %v)", version, m.Supported)
}
