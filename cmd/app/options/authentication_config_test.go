// Copyright Jetstack Ltd. See LICENSE for details.
package options

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/cobra"
)

func TestAuthenticationConfigValidate(t *testing.T) {
	existing := filepath.Join(t.TempDir(), "auth.yaml")
	if err := os.WriteFile(existing, []byte("kind: AuthenticationConfiguration\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	tests := map[string]struct {
		file    string
		wantErr bool
	}{
		"unset is fine":       {},
		"existing file":       {file: existing},
		"missing file errors": {file: filepath.Join(t.TempDir(), "missing.yaml"), wantErr: true},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			o := &AuthenticationConfigOptions{ConfigFile: tc.file}
			if err := o.Validate(); (err != nil) != tc.wantErr {
				t.Fatalf("Validate() error = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}

func TestAuthenticationConfigFlagReachesOptionsThroughTheCommand(t *testing.T) {
	o := New()
	cmd := &cobra.Command{Use: "test"}
	o.AddFlags(cmd)
	if err := cmd.ParseFlags([]string{"--authentication-config=/etc/kop/auth.yaml"}); err != nil {
		t.Fatal(err)
	}
	if o.AuthenticationConfig.ConfigFile != "/etc/kop/auth.yaml" {
		t.Fatalf("ConfigFile = %q", o.AuthenticationConfig.ConfigFile)
	}
}
