// Copyright Jetstack Ltd. See LICENSE for details.
package httpserve

import (
	"context"
	"errors"
	"net"
	"net/http"
	"testing"
	"time"
)

func newServer(h http.Handler) *http.Server {
	return &http.Server{Addr: "127.0.0.1:0", Handler: h, ReadHeaderTimeout: time.Second}
}

func TestStartReturnsListenError(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	srv := &http.Server{Addr: ln.Addr().String(), ReadHeaderTimeout: time.Second}
	if _, err := Start(context.Background(), srv, time.Second, nil); err == nil {
		t.Fatal("Start on a bound port returned nil error")
	}
}

func TestCancelShutsDownCleanly(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	s, err := Start(ctx, newServer(http.NotFoundHandler()), time.Second, func(error) { t.Error("onFailed called on a clean stop") })
	if err != nil {
		t.Fatal(err)
	}
	if s.Addr() == "" {
		t.Fatal("Addr is empty after a successful bind")
	}

	resp, err := http.Get("http://" + s.Addr() + "/")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	cancel()
	if err := s.Wait(); err != nil {
		t.Fatalf("Wait after a clean shutdown = %v", err)
	}
}

func TestListenerFailureIsReported(t *testing.T) {
	var reported error
	s, err := Start(context.Background(), newServer(http.NotFoundHandler()), time.Second, func(err error) { reported = err })
	if err != nil {
		t.Fatal(err)
	}

	if err := s.CloseListener(); err != nil {
		t.Fatal(err)
	}
	waitErr := s.Wait()
	if waitErr == nil {
		t.Fatal("Wait returned nil after the listener was closed under Serve")
	}
	if !errors.Is(reported, waitErr) {
		t.Fatalf("onFailed was not told about %v", waitErr)
	}
}

func TestShutdownTimeoutIsReported(t *testing.T) {
	entered := make(chan struct{}, 1)
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	h := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		entered <- struct{}{}
		<-release
	})

	ctx, cancel := context.WithCancel(context.Background())
	s, err := Start(ctx, newServer(h), 50*time.Millisecond, nil)
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		resp, err := http.Get("http://" + s.Addr() + "/")
		if err == nil {
			resp.Body.Close()
		}
	}()
	<-entered

	cancel()
	if err := s.Wait(); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Wait = %v, want the shutdown deadline", err)
	}
}
