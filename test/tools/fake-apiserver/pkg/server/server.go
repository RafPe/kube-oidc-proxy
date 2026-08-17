// Copyright Jetstack Ltd. See LICENSE for details.
package server

import (
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"sort"
	"strings"

	"k8s.io/klog/v2"
)

// hopByHopHeaders are connection and framing headers that must not be copied
// from the request onto the response. Reflecting them corrupts the response —
// most obviously a Content-Length that disagrees with the echoed body.
var hopByHopHeaders = map[string]bool{
	"Connection":          true,
	"Content-Length":      true,
	"Keep-Alive":          true,
	"Proxy-Authenticate":  true,
	"Proxy-Authorization": true,
	"Te":                  true,
	"Trailer":             true,
	"Transfer-Encoding":   true,
	"Upgrade":             true,
}

type Server struct {
	keyFile, certFile string

	stopCh <-chan struct{}
}

func New(keyFile, certFile string, stopCh <-chan struct{}) (*Server, error) {
	b, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(b)
	if block == nil {
		return nil,
			fmt.Errorf("failed to parse PEM block containing the key: %q", keyFile)
	}

	return &Server{
		keyFile:  keyFile,
		certFile: certFile,
		stopCh:   stopCh,
	}, nil
}

func (s *Server) Run(bindAddress, listenPort string) (<-chan struct{}, error) {
	serveAddr := fmt.Sprintf("%s:%s", bindAddress, listenPort)

	l, err := net.Listen("tcp", serveAddr)
	if err != nil {
		return nil, err
	}

	go func() {
		<-s.stopCh
		if l != nil {
			l.Close()
		}
	}()

	compCh := make(chan struct{})
	go func() {
		defer close(compCh)

		err := http.ServeTLS(l, s, s.certFile, s.keyFile)
		if err != nil {
			klog.Errorf("stopped serving TLS (%s): %s", serveAddr, err)
		}
	}()

	klog.Infof("fake API server listening and serving on %s", serveAddr)

	return compCh, nil
}

func (s *Server) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	klog.Infof("(%s) Fake API server received url %s", r.RemoteAddr, r.URL)

	// Log header names only, never values. The proxy forwards end-user
	// credentials upstream (Authorization, Impersonate-*) and this tool's logs
	// are collected as CI artifacts, so values must not be written out.
	klog.Infof("(%s) Request header names: %s",
		r.RemoteAddr, strings.Join(headerNames(r.Header), ", "))

	// Echo the request headers back. The e2e "Headers" case asserts on the
	// Impersonate-Extra-* headers the proxy added by reading them off this
	// response, so this reflection is the tool's contract.
	for k, vs := range r.Header {
		if hopByHopHeaders[http.CanonicalHeaderKey(k)] {
			continue
		}
		for _, v := range vs {
			rw.Header().Add(k, v)
		}
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		klog.Errorf("failed to read request body: %s", err)
		rw.WriteHeader(http.StatusInternalServerError)
		return
	}

	klog.Infof("(%s) Request body: %d bytes", r.RemoteAddr, len(body))

	// The body is caller-controlled and echoed back verbatim, so pin the
	// response to an opaque type and forbid MIME sniffing — a client must never
	// interpret it as HTML. Set (not Add) after the echo loop above, so a
	// reflected request Content-Type cannot win.
	rw.Header().Set("Content-Type", "application/octet-stream")
	rw.Header().Set("X-Content-Type-Options", "nosniff")

	// WriteHeader must precede Write: writing first implicitly commits a 200 and
	// reduces any later WriteHeader to a no-op that logs a superfluous call.
	rw.WriteHeader(http.StatusOK)

	if _, err := rw.Write(body); err != nil {
		klog.Errorf("failed to write request body to response: %s", err)
	}
}

// headerNames returns the sorted header names present on h, so requests can be
// logged without exposing header values.
func headerNames(h http.Header) []string {
	names := make([]string, 0, len(h))
	for k := range h {
		names = append(names, k)
	}
	sort.Strings(names)

	return names
}
