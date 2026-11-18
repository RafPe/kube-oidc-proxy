// Copyright Jetstack Ltd. See LICENSE for details.
package authn

import (
	"strings"
	"testing"
)

func TestExpandIssuerName(t *testing.T) {
	tests := []struct {
		name    string
		expr    string
		want    string
		wantErr string
	}{
		{
			name: "an expression without the variable stays",
			expr: `"one:" + claims.sub`,
			want: `"one:" + claims.sub`,
		},
		{
			name: "the variable becomes a string literal",
			expr: `authenticationConfiguration.issuer.name + ":" + claims.sub`,
			want: `"gha-vendor" + ":" + claims.sub`,
		},
		{
			name: "each reference is replaced",
			expr: `authenticationConfiguration.issuer.name + ":" + claims.sub + "@" + authenticationConfiguration.issuer.name`,
			want: `"gha-vendor" + ":" + claims.sub + "@" + "gha-vendor"`,
		},
		{
			name: "whitespace around a dot is permitted",
			expr: "authenticationConfiguration . issuer\n.name + claims.sub",
			want: `"gha-vendor" + claims.sub`,
		},
		{
			name: "a reference inside a macro is replaced",
			expr: `claims.groups.map(g, authenticationConfiguration.issuer.name + ":" + g)`,
			want: `claims.groups.map(g, "gha-vendor" + ":" + g)`,
		},
		{
			name: "the same text in a string literal stays",
			expr: `"authenticationConfiguration.issuer.name" + claims.sub`,
			want: `"authenticationConfiguration.issuer.name" + claims.sub`,
		},
		{
			name: "text after a multi-byte character keeps its position",
			expr: `"é:" + authenticationConfiguration.issuer.name`,
			want: `"é:" + "gha-vendor"`,
		},
		{
			name: "an expression that does not parse stays for the upstream error",
			expr: `authenticationConfiguration.issuer.name +`,
			want: `authenticationConfiguration.issuer.name +`,
		},
		{
			name:    "another field of the issuer is refused",
			expr:    `authenticationConfiguration.issuer.url + claims.sub`,
			wantErr: `"authenticationConfiguration.issuer.name" is the only field`,
		},
		{
			name:    "the root alone is refused",
			expr:    `string(authenticationConfiguration) + claims.sub`,
			wantErr: `"authenticationConfiguration.issuer.name" is the only field`,
		},
		{
			name:    "a presence test is refused",
			expr:    `has(authenticationConfiguration.issuer.name)`,
			wantErr: `"authenticationConfiguration.issuer.name" is the only field`,
		},
		{
			name:    "a comment inside the reference is refused",
			expr:    "authenticationConfiguration. // why\nissuer.name + claims.sub",
			wantErr: "without comments",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := expandIssuerName(tc.expr, "gha-vendor")
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("expandIssuerName() error = %v, want it to contain %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("expandIssuerName() unexpected error: %v", err)
			}
			if got != tc.want {
				t.Fatalf("expandIssuerName() = %q, want %q", got, tc.want)
			}
		})
	}
}
