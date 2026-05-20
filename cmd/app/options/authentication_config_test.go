// Copyright Jetstack Ltd. See LICENSE for details.
package options

import (
	"os"
	"path/filepath"
	"testing"
)

func writeFile(t *testing.T, content string) string {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "auth-config-*.yaml")
	if err != nil {
		t.Fatalf("creating temp file: %v", err)
	}
	if _, err := f.WriteString(content); err != nil {
		t.Fatalf("writing temp file: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("closing temp file: %v", err)
	}
	return f.Name()
}

func TestAuthenticationConfigOptions_Validate(t *testing.T) {
	existingFile := writeFile(t, "")

	tests := map[string]struct {
		configFile string
		wantErr    bool
	}{
		"empty config file is valid (flag not set)": {
			configFile: "",
			wantErr:    false,
		},
		"existing file is valid": {
			configFile: existingFile,
			wantErr:    false,
		},
		"non-existent file is an error": {
			configFile: filepath.Join(t.TempDir(), "does-not-exist.yaml"),
			wantErr:    true,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			o := &AuthenticationConfigOptions{ConfigFile: tc.configFile}
			err := o.Validate()
			if (err != nil) != tc.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}

func TestAuthenticationConfigOptions_Load(t *testing.T) {
	validConfig := `
apiVersion: apiserver.config.k8s.io/v1beta1
kind: AuthenticationConfiguration
jwt:
  - issuer:
      url: https://vault.example.com/v1/identity/oidc
      audiences:
        - my-client
    claimMappings:
      username:
        claim: email
        prefix: ""
      groups:
        claim: groups
        prefix: ""
  - issuer:
      url: https://issuer2.example.com/v1/identity/oidc
      audiences:
        - kubernetes
    claimMappings:
      username:
        claim: email
        prefix: ""
      groups:
        claim: groups
        prefix: ""
`

	tests := map[string]struct {
		content    string
		wantErr    bool
		wantJWTLen int
	}{
		"valid config with two issuers": {
			content:    validConfig,
			wantJWTLen: 2,
		},
		"invalid YAML": {
			content: "not: valid: yaml: [",
			wantErr: true,
		},
		"empty JWT list is an error": {
			content: `
apiVersion: apiserver.config.k8s.io/v1beta1
kind: AuthenticationConfiguration
jwt: []
`,
			wantErr: true,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			path := writeFile(t, tc.content)
			o := &AuthenticationConfigOptions{ConfigFile: path}

			cfg, err := o.Load()
			if (err != nil) != tc.wantErr {
				t.Fatalf("Load() error = %v, wantErr %v", err, tc.wantErr)
			}
			if tc.wantErr {
				return
			}
			if got := len(cfg.JWT); got != tc.wantJWTLen {
				t.Errorf("Load() JWT count = %d, want %d", got, tc.wantJWTLen)
			}
		})
	}
}

func TestAuthenticationConfigOptions_Load_FileNotFound(t *testing.T) {
	o := &AuthenticationConfigOptions{ConfigFile: "/does/not/exist.yaml"}
	_, err := o.Load()
	if err == nil {
		t.Error("Load() expected error for missing file, got nil")
	}
}
