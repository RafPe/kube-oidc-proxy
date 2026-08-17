// Copyright Jetstack Ltd. See LICENSE for details.
package token

import (
	"net/http"
	"strings"
	"testing"
)

// FuzzParseFromRequest drives bearer-token extraction with arbitrary
// Authorization headers. The header is fully attacker-controlled on every
// request the proxy serves, so extraction must never panic and must only hand
// back a token when the header really is a "bearer <token>" pair.
func FuzzParseFromRequest(f *testing.F) {
	for _, seed := range []string{
		"",
		"bearer abc",
		"Bearer abc",
		"BEARER  abc",
		"bearer",
		"bearer ",
		"  bearer abc  ",
		"basic abc",
		"bearer abc def",
		"bearer\tabc",
		"bearerabc",
	} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, auth string) {
		req, err := http.NewRequest(http.MethodGet, "http://localhost/", nil)
		if err != nil {
			t.Fatalf("building request: %s", err)
		}
		// Assign directly: Header.Set would reject values the wire can carry.
		req.Header["Authorization"] = []string{auth}

		token, ok := ParseFromRequest(req)

		if !ok {
			if token != "" {
				t.Fatalf("token %q returned alongside ok=false", token)
			}
			return
		}

		if token == "" {
			t.Fatal("ok=true with an empty token")
		}
		if strings.Contains(token, " ") {
			t.Fatalf("token %q contains a space", token)
		}

		trimmed := strings.TrimSpace(auth)
		if !strings.HasPrefix(strings.ToLower(trimmed), "bearer ") {
			t.Fatalf("token accepted from a non-bearer header %q", auth)
		}
		if !strings.Contains(trimmed, token) {
			t.Fatalf("token %q is not a substring of header %q", token, auth)
		}
	})
}
