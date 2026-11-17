// Copyright Jetstack Ltd. See LICENSE for details.
package options

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestOIDCAuthenticationOptions_Validate(t *testing.T) {
	// A real, readable CA file for the happy-path and non-regression cases.
	readableCA := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(readableCA, []byte("-----BEGIN CERTIFICATE-----\n"), 0600); err != nil {
		t.Fatalf("writing temp CA file: %v", err)
	}

	tests := map[string]struct {
		issuerURL     string
		clientID      string
		caFile        string
		authConfigSet bool
		wantErr       bool
	}{
		"both issuer URL and client ID set is valid": {
			issuerURL: "https://vault.example.com",
			clientID:  "my-client",
			wantErr:   false,
		},
		"empty CA file path is valid (uses system roots)": {
			issuerURL: "https://vault.example.com",
			clientID:  "my-client",
			caFile:    "",
			wantErr:   false,
		},
		"readable CA file is valid": {
			issuerURL: "https://vault.example.com",
			clientID:  "my-client",
			caFile:    readableCA,
			wantErr:   false,
		},
		"unreadable CA file is an error": {
			issuerURL: "https://vault.example.com",
			clientID:  "my-client",
			caFile:    "/does/not/exist/ca.pem",
			wantErr:   true,
		},
		"unreadable CA file is ignored when authentication-config is set": {
			caFile:        "/does/not/exist/ca.pem",
			authConfigSet: true,
			wantErr:       false,
		},
		"neither issuer URL nor client ID set is valid": {
			wantErr: false,
		},
		"issuer URL without client ID is an error": {
			issuerURL: "https://vault.example.com",
			wantErr:   true,
		},
		"client ID without issuer URL is an error": {
			clientID: "my-client",
			wantErr:  true,
		},
		"missing flags are ignored when authentication-config is set": {
			issuerURL:     "",
			clientID:      "",
			authConfigSet: true,
			wantErr:       false,
		},
		"mismatched flags are ignored when authentication-config is set": {
			issuerURL:     "https://vault.example.com",
			clientID:      "",
			authConfigSet: true,
			wantErr:       false,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			o := &OIDCAuthenticationOptions{
				IssuerURL: tc.issuerURL,
				ClientID:  tc.clientID,
				CAFile:    tc.caFile,
			}
			err := o.Validate()
			if err == nil && !tc.authConfigSet {
				err = o.ValidateIssuerFlags()
			}
			if (err != nil) != tc.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}

// TestValidateIssuerFlagsReportsEveryProblem pins that the single-issuer
// validator does not stop at the first problem: an operator sees the
// pairing, CA file and prefix mistakes of one command line in one run.
func TestValidateIssuerFlagsReportsEveryProblem(t *testing.T) {
	o := &OIDCAuthenticationOptions{
		IssuerURL:      "https://vault.example.com",
		CAFile:         "/does/not/exist/ca.pem",
		UsernamePrefix: "system:",
		GroupsPrefix:   "system:",
	}
	err := o.ValidateIssuerFlags()
	if err == nil {
		t.Fatal("ValidateIssuerFlags() = nil, want every problem reported")
	}
	for _, want := range []string{
		"--oidc-issuer-url and --oidc-client-id must be specified together",
		`--oidc-ca-file "/does/not/exist/ca.pem"`,
		`--oidc-username-prefix "system:"`,
		`--oidc-groups-prefix "system:"`,
	} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("ValidateIssuerFlags() = %q, missing %q", err, want)
		}
	}
}

func TestOIDCAuthenticationOptionsValidateTLSClientCredentials(t *testing.T) {
	tests := map[string]struct {
		certFile string
		keyFile  string
		wantErr  bool
	}{
		"neither file is valid": {},
		"certificate without key is rejected": {
			certFile: "/tmp/client.crt",
			wantErr:  true,
		},
		"key without certificate is rejected": {
			keyFile: "/tmp/client.key",
			wantErr: true,
		},
		"unreadable pair is rejected": {
			certFile: "/does/not/exist/client.crt",
			keyFile:  "/does/not/exist/client.key",
			wantErr:  true,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			o := &OIDCAuthenticationOptions{
				TLSClientCertFile: tc.certFile,
				TLSClientKeyFile:  tc.keyFile,
			}
			err := o.Validate()
			if gotErr := err != nil; gotErr != tc.wantErr {
				t.Errorf("Validate() error = %v, want error presence = %t", err, tc.wantErr)
			}
		})
	}
}
