// Copyright Jetstack Ltd. See LICENSE for details.
package kind

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	log "github.com/sirupsen/logrus"
	"sigs.k8s.io/kind/pkg/cluster/nodeutils"
)

const (
	ProxyImageName         = "kube-oidc-proxy-e2e"
	IssuerImageName        = "oidc-issuer-e2e"
	FakeAPIServerImageName = "fake-apiserver-e2e"
	AuditWebhookImageName  = "audit-webhook-e2e"
)

func (k *Kind) LoadAllImages() error {
	if err := k.LoadKubeOIDCProxy(); err != nil {
		return err
	}

	if err := k.LoadIssuer(); err != nil {
		return err
	}

	if err := k.LoadFakeAPIServer(); err != nil {
		return err
	}

	if err := k.LoadAuditWebhook(); err != nil {
		return err
	}

	return nil
}

func (k *Kind) LoadKubeOIDCProxy() error {
	// The proxy Dockerfile copies bin/${TARGETARCH}/kube-oidc-proxy. Under
	// BuildKit TARGETARCH resolves to the build host architecture, so build the
	// binary into the matching arch subdirectory and pass TARGETARCH explicitly
	// for builders that do not populate it automatically.
	binPath := filepath.Join(k.rootPath, "bin", runtime.GOARCH, "kube-oidc-proxy")
	mainPath := filepath.Join(k.rootPath, "./cmd/.")

	return k.loadImage(binPath, mainPath, ProxyImageName, k.rootPath,
		"--build-arg", "TARGETARCH="+runtime.GOARCH)
}

func (k *Kind) LoadIssuer() error {
	binPath := filepath.Join(k.rootPath, "./test/tools/issuer/bin/oidc-issuer-linux")
	dockerfilePath := filepath.Join(k.rootPath, "./test/tools/issuer")
	mainPath := filepath.Join(dockerfilePath, "cmd")

	return k.loadImage(binPath, mainPath, IssuerImageName, dockerfilePath)
}

func (k *Kind) LoadFakeAPIServer() error {
	binPath := filepath.Join(k.rootPath, "./test/tools/fake-apiserver/bin/fake-apiserver-linux")
	dockerfilePath := filepath.Join(k.rootPath, "./test/tools/fake-apiserver")
	mainPath := filepath.Join(dockerfilePath, "cmd")

	return k.loadImage(binPath, mainPath, FakeAPIServerImageName, dockerfilePath)
}

func (k *Kind) LoadAuditWebhook() error {
	binPath := filepath.Join(k.rootPath, "./test/tools/audit-webhook/bin/audit-webhook")
	dockerfilePath := filepath.Join(k.rootPath, "./test/tools/audit-webhook")
	mainPath := filepath.Join(dockerfilePath, "cmd")

	return k.loadImage(binPath, mainPath, AuditWebhookImageName, dockerfilePath)
}

func (k *Kind) loadImage(binPath, mainPath, image, dockerfilePath string, extraBuildArgs ...string) error {
	log.Infof("kind: building %q", mainPath)

	if err := os.MkdirAll(filepath.Dir(binPath), 0755); err != nil {
		return err
	}

	err := k.runCmd("go", "build", "-v", "-o", binPath, mainPath)
	if err != nil {
		return err
	}

	buildArgs := append([]string{"build"}, extraBuildArgs...)
	buildArgs = append(buildArgs, "-t", image, dockerfilePath)
	err = k.runCmd("docker", buildArgs...)
	if err != nil {
		return err
	}

	tmpDir, err := os.MkdirTemp(os.TempDir(), "kube-oidc-proxy-e2e")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmpDir)

	imageArchive := filepath.Join(tmpDir, fmt.Sprintf("%s-e2e.tar", image))
	log.Infof("kind: saving image to archive %q", imageArchive)

	err = k.runCmd("docker", "save", "--output="+imageArchive, image)
	if err != nil {
		return err
	}

	nodes, err := k.Nodes()
	if err != nil {
		return err
	}

	b, err := os.ReadFile(imageArchive)
	if err != nil {
		return err
	}

	for _, node := range nodes {
		log.Infof("kind: loading image %q to node %q", image, node.String())
		r := bytes.NewBuffer(b)
		if err := nodeutils.LoadImageArchive(node, r); err != nil {
			return err
		}

		err := node.Command("mkdir", "-p", "/tmp/kube-oidc-proxy").Run()
		if err != nil {
			return fmt.Errorf("failed to create directory %q: %s",
				"/tmp/kube-oidc-proxy", err)
		}
	}

	return nil
}

func (k *Kind) runCmd(command string, args ...string) error {
	return k.runCmdWithOut(os.Stdout, command, args...)
}

func (k *Kind) runCmdWithOut(w io.Writer, command string, args ...string) error {
	log.Infof("kind: running command '%s %s'", command, strings.Join(args, " "))
	cmd := exec.Command(command, args...)

	cmd.Stderr = os.Stderr
	cmd.Stdout = w
	cmd.Env = append(cmd.Env,
		"GO111MODULE=on", "CGO_ENABLED=0", "HOME="+os.Getenv("HOME"),
		"PATH="+os.Getenv("PATH"),
		// Build test images for the host architecture so the resulting binaries
		// run on the kind nodes (which match the host arch). Forcing amd64 here
		// breaks pod startup with "exec format error" on arm64 hosts.
		"GOARCH="+runtime.GOARCH, "GOOS=linux")

	if err := cmd.Start(); err != nil {
		return err
	}

	if err := cmd.Wait(); err != nil {
		return err
	}

	return nil
}
