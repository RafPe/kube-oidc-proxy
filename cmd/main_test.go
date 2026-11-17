// Copyright Jetstack Ltd. See LICENSE for details.
package main

import (
	"bytes"
	"io"
	"strings"
	"testing"
)

// TestRunReportsFlagErrorsOnStderr pins the one error path main owns: a
// failure before the logger exists is printed once, prefixed, and the process
// exits non-zero.
func TestRunReportsFlagErrorsOnStderr(t *testing.T) {
	var stderr bytes.Buffer
	if code := run([]string{"--no-such-flag"}, io.Discard, &stderr); code != 1 {
		t.Fatalf("exit status = %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), "error: unknown flag: --no-such-flag") {
		t.Fatalf("stderr = %q, want the flag error reported once with the error: prefix", stderr.String())
	}
}

// TestRunReportsValidationErrors pins that an invalid configuration is
// refused before anything is started, with the reason on stderr.
func TestRunReportsValidationErrors(t *testing.T) {
	var stderr bytes.Buffer
	if code := run([]string{"--oidc-issuer-url=https://issuer.example.com"}, io.Discard, &stderr); code != 1 {
		t.Fatalf("exit status = %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), "--oidc-issuer-url and --oidc-client-id must be specified together") {
		t.Fatalf("stderr = %q, want the validation error", stderr.String())
	}
}

// TestRunPrintsVersionAndExitsZero pins that --version is answered on stdout
// and ends the process through main's exit status, not from inside the
// command.
func TestRunPrintsVersionAndExitsZero(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"--version"}, &stdout, &stderr); code != 0 {
		t.Fatalf("exit status = %d, want 0; stderr = %q", code, stderr.String())
	}
	if !strings.HasPrefix(stdout.String(), "kube-oidc-proxy version: ") {
		t.Fatalf("stdout = %q, want the version information", stdout.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want nothing", stderr.String())
	}
}
