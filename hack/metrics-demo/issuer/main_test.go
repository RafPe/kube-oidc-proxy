// Copyright Jetstack Ltd. See LICENSE for details.
package main

import (
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
)

func TestServingCertFromSecret(t *testing.T) {
	tests := []struct {
		name    string
		secret  *corev1.Secret
		want    string
		wantErr string
	}{
		{
			name:   "tls secret with a certificate",
			secret: &corev1.Secret{Type: corev1.SecretTypeTLS, Data: map[string][]byte{corev1.TLSCertKey: []byte("CERT"), corev1.TLSPrivateKeyKey: []byte("KEY")}},
			want:   "CERT",
		},
		{
			name:    "wrong type",
			secret:  &corev1.Secret{Type: corev1.SecretTypeOpaque, Data: map[string][]byte{corev1.TLSCertKey: []byte("CERT")}},
			wantErr: "type Opaque, want kubernetes.io/tls",
		},
		{
			name:    "missing certificate key",
			secret:  &corev1.Secret{Type: corev1.SecretTypeTLS, Data: map[string][]byte{corev1.TLSPrivateKeyKey: []byte("KEY")}},
			wantErr: "no tls.crt",
		},
		{
			name:    "empty certificate",
			secret:  &corev1.Secret{Type: corev1.SecretTypeTLS, Data: map[string][]byte{corev1.TLSCertKey: {}}},
			wantErr: "no tls.crt",
		},
		{
			name:    "nil data",
			secret:  &corev1.Secret{Type: corev1.SecretTypeTLS},
			wantErr: "no tls.crt",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := servingCertFromSecret(tt.secret)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("servingCertFromSecret() error = %v, want it to contain %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("servingCertFromSecret() unexpected error: %v", err)
			}
			if string(got) != tt.want {
				t.Fatalf("servingCertFromSecret() = %q, want %q", got, tt.want)
			}
		})
	}
}
