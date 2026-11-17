// Copyright Jetstack Ltd. See LICENSE for details.

// Package echo is the HTTP echo server the upgrade e2e cases exec and
// port-forward into. It replaces gcr.io/google_containers/echoserver:1.10, an
// amd64-only image on a retired registry that had to be pulled over the
// network on every run, and keeps the same response shape so the cases'
// assertions are unchanged.
package echo

import (
	"fmt"
	"io"
	"net/http"
	"os"
)

// Handler echoes each request back as text, and answers /ready for the pod
// readiness probe so a case never execs into the pod before it is listening.
func Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/ready", func(rw http.ResponseWriter, _ *http.Request) {
		rw.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/", echo)
	return mux
}

func echo(rw http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(rw, err.Error(), http.StatusBadRequest)
		return
	}

	hostname, _ := os.Hostname()

	rw.Header().Set("Content-Type", "text/plain")
	fmt.Fprintf(rw, "Hostname: %s\n\n", hostname)
	fmt.Fprintf(rw, "Request Information:\n\tmethod=%s\n\turi=%s\n\n", r.Method, r.RequestURI)
	fmt.Fprintf(rw, "Request Body:\n%s\n", body)
}
