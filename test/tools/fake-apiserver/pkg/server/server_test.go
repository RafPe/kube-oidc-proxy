// Copyright Jetstack Ltd. See LICENSE for details.
package server

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The e2e "Headers" case (test/e2e/suite/cases/headers) asserts on the
// Impersonate-Extra-* headers the proxy adds by reading them back off this
// server's response. These tests pin that reflection contract so it cannot be
// broken by hardening the handler.
func TestServeHTTP_ReflectsRequestHeadersAndBody(t *testing.T) {
	body := "some-request-body"
	req := httptest.NewRequest(http.MethodPost, "/foo/bar", strings.NewReader(body))
	req.Header.Add("Impersonate-Extra-Key1", "foo")
	req.Header.Add("Impersonate-Extra-Key1", "bar")
	req.Header.Set("Impersonate-Extra-Key2", "foo")

	rec := httptest.NewRecorder()
	new(Server).ServeHTTP(rec, req)

	resp := rec.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("unexpected status: got=%d want=%d", resp.StatusCode, http.StatusOK)
	}

	for k, want := range map[string][]string{
		"Impersonate-Extra-Key1": {"foo", "bar"},
		"Impersonate-Extra-Key2": {"foo"},
	} {
		got := resp.Header.Values(k)
		if strings.Join(got, ",") != strings.Join(want, ",") {
			t.Errorf("header %q: got=%v want=%v", k, got, want)
		}
	}

	got, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("reading response body: %s", err)
	}
	if string(got) != body {
		t.Errorf("body: got=%q want=%q", got, body)
	}
}

// The echoed body is caller-controlled, so the response must never invite a
// client to interpret it as HTML.
func TestServeHTTP_BodyIsNotInterpretableAsHTML(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("<script>alert(1)</script>"))
	// A reflected request Content-Type must not survive onto the response.
	req.Header.Set("Content-Type", "text/html")

	rec := httptest.NewRecorder()
	new(Server).ServeHTTP(rec, req)

	resp := rec.Result()
	defer resp.Body.Close()

	if got, want := resp.Header.Get("Content-Type"), "application/octet-stream"; got != want {
		t.Errorf("Content-Type: got=%q want=%q", got, want)
	}
	if got, want := resp.Header.Get("X-Content-Type-Options"), "nosniff"; got != want {
		t.Errorf("X-Content-Type-Options: got=%q want=%q", got, want)
	}
}

// Reflecting the request's framing headers would corrupt the response, since the
// handler writes its own body.
func TestServeHTTP_DoesNotReflectFramingHeaders(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("abc"))
	req.Header.Set("Content-Length", "99999")
	req.Header.Set("Transfer-Encoding", "chunked")
	req.Header.Set("Connection", "close")

	rec := httptest.NewRecorder()
	new(Server).ServeHTTP(rec, req)

	// Inspect the recorder's header map directly: http.Response synthesises
	// framing fields, which would mask what the handler actually set.
	for _, k := range []string{"Transfer-Encoding", "Connection"} {
		if got := rec.Header().Get(k); got != "" {
			t.Errorf("header %q should not be reflected, got=%q", k, got)
		}
	}
	if got := rec.Header().Get("Content-Length"); got == "99999" {
		t.Errorf("request Content-Length was reflected onto the response: %q", got)
	}
}

func TestHeaderNamesAreSortedAndExcludeValues(t *testing.T) {
	h := http.Header{}
	h.Set("Zulu", "secret-token")
	h.Set("Alpha", "secret-token")
	h.Set("Mike", "secret-token")

	got := strings.Join(headerNames(h), ", ")
	if want := "Alpha, Mike, Zulu"; got != want {
		t.Errorf("headerNames: got=%q want=%q", got, want)
	}
	if strings.Contains(got, "secret-token") {
		t.Errorf("headerNames leaked a header value: %q", got)
	}
}
