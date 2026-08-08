// Copyright Jetstack Ltd. See LICENSE for details.
package proxy

import (
	"testing"
)

func TestParseTrustedProxies(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		in      []string
		wantLen int
		wantErr bool
	}{
		"nil is no trust": {
			in:      nil,
			wantLen: 0,
		},
		"empty slice is no trust": {
			in:      []string{},
			wantLen: 0,
		},
		"valid IPv4 CIDRs": {
			in:      []string{"10.0.0.0/8", "192.168.0.0/16"},
			wantLen: 2,
		},
		"valid IPv6 CIDR": {
			in:      []string{"fd00::/8"},
			wantLen: 1,
		},
		"whitespace is trimmed": {
			in:      []string{" 10.0.0.0/8 "},
			wantLen: 1,
		},
		"bare IP without mask is rejected": {
			in:      []string{"10.0.0.1"},
			wantErr: true,
		},
		"garbage is rejected": {
			in:      []string{"not-a-cidr"},
			wantErr: true,
		},
		"empty entry is rejected": {
			in:      []string{"10.0.0.0/8", ""},
			wantErr: true,
		},
	}

	for name, tc := range tests {
		tc := tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			got, err := parseTrustedProxies(tc.in)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("parseTrustedProxies(%v) = nil error, want error", tc.in)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseTrustedProxies(%v) unexpected error: %v", tc.in, err)
			}
			if len(got) != tc.wantLen {
				t.Errorf("parseTrustedProxies(%v) len = %d, want %d", tc.in, len(got), tc.wantLen)
			}
		})
	}
}
