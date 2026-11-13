// Copyright Jetstack Ltd. See LICENSE for details.
package authn

import "testing"

// TestIssuerNameNeverEmitsRawInput pins the binding constraint that a full
// issuer URL never reaches the log stream. A value the URL parser cannot turn
// into a host must degrade to a fixed placeholder, not to the input itself:
// falling back to the raw string is exactly the leak the constraint forbids.
func TestIssuerNameNeverEmitsRawInput(t *testing.T) {
	tests := map[string]struct {
		issuerURL string
		want      string
	}{
		"host is kept":           {issuerURL: "https://idp.example.com/realms/corp", want: "idp.example.com"},
		"host with port":         {issuerURL: "https://idp.example.com:8443/", want: "idp.example.com:8443"},
		"no scheme, no host":     {issuerURL: "idp.example.com/realms/corp", want: "unknown"},
		"unparsable":             {issuerURL: "https://exa mple.com/%zz", want: "unknown"},
		"control characters":     {issuerURL: "not a url\nissuer=secret", want: "unknown"},
		"empty":                  {issuerURL: "", want: "unknown"},
		"opaque scheme, no host": {issuerURL: "mailto:idp@example.com", want: "unknown"},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			got := IssuerName(tc.issuerURL)
			if got != tc.want {
				t.Fatalf("IssuerName(%q) = %q, want %q", tc.issuerURL, got, tc.want)
			}
			// The stronger property: whatever the input, the output is either a
			// bare host or the placeholder. It is never the input.
			if got != "unknown" && got == tc.issuerURL {
				t.Fatalf("IssuerName(%q) returned its own input", tc.issuerURL)
			}
		})
	}
}
