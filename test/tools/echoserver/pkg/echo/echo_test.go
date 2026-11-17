// Copyright Jetstack Ltd. See LICENSE for details.
package echo

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The upgrade e2e cases exec and port-forward into this server and assert on
// "Request Body:\n<body>", the shape the retired
// gcr.io/google_containers/echoserver:1.10 image produced.
func TestHandlerEchoesRequestBody(t *testing.T) {
	srv := httptest.NewServer(Handler())
	defer srv.Close()

	resp, err := http.Post(srv.URL+"/", "text/plain", strings.NewReader("hello world"))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), "Request Body:\nhello world") {
		t.Fatalf("body does not echo the request body:\n%s", body)
	}
	if !strings.Contains(string(body), "Hostname: ") {
		t.Fatalf("body does not report the hostname:\n%s", body)
	}
}

func TestHandlerServesReadiness(t *testing.T) {
	srv := httptest.NewServer(Handler())
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/ready")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("/ready status = %d, want 200", resp.StatusCode)
	}
}
