// Copyright Jetstack Ltd. See LICENSE for details.
package environment

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/rafpe/kube-oidc-proxy/test/e2e/versions"
	"github.com/rafpe/kube-oidc-proxy/test/kind"
)

const (
	defaultRootPath = "../../."
)

// Environment is the kind cluster the e2e suite and the dev tool run against,
// together with the repository root its images are built from.
type Environment struct {
	kind     *kind.Kind
	rootPath string
}

func New(masterNodesCount, workerNodesCount int) (*Environment, error) {
	version := os.Getenv("KUBE_OIDC_PROXY_K8S_VERSION")
	if version == "" {
		version = versions.Latest()
	}
	// Resolve through the committed manifest: digest-pinned image, loud
	// failure on versions this commit does not declare support for.
	nodeImage, err := versions.ImageFor(version)
	if err != nil {
		return nil, err
	}

	rootPath, err := RootPath()
	if err != nil {
		return nil, err
	}

	kind := kind.New(rootPath, nodeImage, masterNodesCount, workerNodesCount)

	return &Environment{
		rootPath: rootPath,
		kind:     kind,
	}, nil
}

func (e *Environment) Create() error {
	if err := e.kind.Create(); err != nil {
		return fmt.Errorf("failed to create kind cluster: %w", err)
	}

	return e.LoadImages()
}

// LoadImages builds and loads every image the suite deploys into the cluster.
func (e *Environment) LoadImages() error {
	return e.kind.LoadAllImages()
}

func (e *Environment) Destroy() error {
	if e.kind != nil {
		if err := e.kind.Destroy(); err != nil {
			return err
		}
	}

	return nil
}

func (e *Environment) KubeConfigPath() string {
	return e.kind.KubeConfigPath()
}

func (e *Environment) RootPath() string {
	return e.rootPath
}

func RootPath() (string, error) {
	rootPath := os.Getenv("KUBE_OIDC_PROXY_ROOT_PATH")
	if rootPath == "" {
		rootPath = defaultRootPath
	}

	rootPath, err := filepath.Abs(rootPath)
	if err != nil {
		return "", fmt.Errorf("failed to get absolute path %q: %w",
			rootPath, err)
	}

	return rootPath, nil
}
