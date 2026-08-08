// Copyright Jetstack Ltd. See LICENSE for details.
package server

import (
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"

	"k8s.io/klog/v2"
)

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
	klog.Infof("(%s) Fake API server received url %s", r.URL, r.RemoteAddr)

	klog.Infof("(%s) Request headers:", r.RemoteAddr)
	for k, vs := range r.Header {
		for _, v := range vs {
			klog.Infof("(%s) %s: %s", r.RemoteAddr, k, v)
			rw.Header().Add(k, v)
		}
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		klog.Errorf("failed to read request body: %s", err)
		rw.WriteHeader(http.StatusInternalServerError)
		return
	}

	klog.Infof("(%s) Request Body: %s", r.RemoteAddr, body)

	if _, err := rw.Write(body); err != nil {
		klog.Errorf("failed to write request body to response: %s", err)
		rw.WriteHeader(http.StatusInternalServerError)
		return
	}

	rw.WriteHeader(http.StatusOK)
}
