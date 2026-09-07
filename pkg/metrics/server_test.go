// Copyright Jetstack Ltd. See LICENSE for details.
package metrics

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rafpe/kube-oidc-proxy/pkg/logging"
	"github.com/rafpe/kube-oidc-proxy/pkg/logging/logtest"
)

func TestServerStartReturnsBindError(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	root, logs := logtest.New(t, 0)
	s := NewServer(ln.Addr().String(), newTestRecorder(t), logging.ForComponent(root, logging.ComponentMetrics))
	err = s.Start(context.Background())
	if err == nil || !strings.Contains(err.Error(), "metrics") {
		t.Fatalf("Start on a busy port = %v, want an error naming the metrics listener", err)
	}
	if len(logs.ByEvent(logging.EventMetricsServerStarted)) != 0 {
		t.Fatal("started record emitted for a listener that never bound")
	}
}

func TestServerServesMetricsAndShutsDownOnContextCancel(t *testing.T) {
	root, logs := logtest.New(t, 0)
	// Bind :0 and read the port back, rather than reserving and releasing a
	// port first, so no other process can take it in between.
	s := NewServer("127.0.0.1:0", newTestRecorder(t), logging.ForComponent(root, logging.ComponentMetrics))

	ctx, cancel := context.WithCancel(context.Background())
	if err := s.Start(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cancel(); _ = s.Wait() })
	addr := s.Addr()
	rec := logs.Only(t, logging.EventMetricsServerStarted)
	if rec.String("address") != addr {
		t.Fatalf("address = %q, want the bound address %q", rec.String("address"), addr)
	}

	resp, err := http.Get("http://" + addr + "/metrics")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), "kube_oidc_proxy_build_info") {
		t.Fatalf("GET /metrics = %d\n%s", resp.StatusCode, body)
	}

	cancel()
	if err := s.Wait(); err != nil {
		t.Fatalf("Wait after a clean shutdown = %v", err)
	}
	if _, err := http.Get("http://" + addr + "/metrics"); err == nil {
		t.Fatal("listener still accepting after shutdown")
	}
	logtest.AssertRegistered(t, logs)
}

func TestServerWaitReportsServeFailure(t *testing.T) {
	// Closing the listener out from under Serve makes it return a non-
	// ErrServerClosed error, which Wait must surface and the server must log.
	root, logs := logtest.New(t, 0)
	s := NewServer("127.0.0.1:0", newTestRecorder(t), logging.ForComponent(root, logging.ComponentMetrics))
	if err := s.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	s.listener.Close()
	if err := s.Wait(); err == nil {
		t.Fatal("Wait returned nil after Serve failed")
	}
	if len(logs.ByEvent(logging.EventMetricsServerFailed)) != 1 {
		t.Fatalf("want one metrics.server.failed record, got: %s", logs.Raw())
	}
}

// blockingRecorderHandler is a stand-in exposition that holds a scrape open
// until released, so a test can observe shutdown draining it.
type blockingRecorderHandler struct {
	entered chan struct{}
	release chan struct{}
}

func (h *blockingRecorderHandler) ServeHTTP(w http.ResponseWriter, _ *http.Request) {
	h.entered <- struct{}{}
	<-h.release
	w.WriteHeader(http.StatusOK)
}

// TestServerWaitDrainsAnActiveScrape pins the lifecycle correction: Wait
// returns after Shutdown has finished, not when Serve returns, so an in-flight
// scrape completes before the process moves on.
func TestServerWaitDrainsAnActiveScrape(t *testing.T) {
	root, _ := logtest.New(t, 0)
	s := NewServer("127.0.0.1:0", newTestRecorder(t), logging.ForComponent(root, logging.ComponentMetrics))
	h := &blockingRecorderHandler{entered: make(chan struct{}, 1), release: make(chan struct{})}
	s.srv.Handler = h

	ctx, cancel := context.WithCancel(context.Background())
	if err := s.Start(ctx); err != nil {
		t.Fatal(err)
	}
	// The body releases the scrape on the happy path and the cleanup releases
	// it on an early t.Fatalf, so the close must happen at most once.
	release := sync.OnceFunc(func() { close(h.release) })
	t.Cleanup(func() { cancel(); release(); _ = s.Wait() })

	scrapeDone := make(chan int, 1)
	go func() {
		resp, err := http.Get("http://" + s.Addr() + "/metrics")
		if err != nil {
			scrapeDone <- 0
			return
		}
		resp.Body.Close()
		scrapeDone <- resp.StatusCode
	}()
	<-h.entered

	cancel()
	waitDone := make(chan error, 1)
	go func() { waitDone <- s.Wait() }()
	select {
	case err := <-waitDone:
		t.Fatalf("Wait returned (%v) while a scrape was still being served", err)
	case <-time.After(200 * time.Millisecond):
	}

	release()
	if err := <-waitDone; err != nil {
		t.Fatalf("Wait after drain = %v", err)
	}
	if code := <-scrapeDone; code != http.StatusOK {
		t.Fatalf("drained scrape finished with %d, want 200", code)
	}
}

// TestServerWaitReportsShutdownTimeout pins that a scrape that will not finish
// inside the shutdown budget is closed and the timeout is returned, never
// swallowed.
func TestServerWaitReportsShutdownTimeout(t *testing.T) {
	root, logs := logtest.New(t, 0)
	s := NewServer("127.0.0.1:0", newTestRecorder(t), logging.ForComponent(root, logging.ComponentMetrics))
	s.shutdownTimeout = 50 * time.Millisecond
	h := &blockingRecorderHandler{entered: make(chan struct{}, 1), release: make(chan struct{})}
	s.srv.Handler = h

	ctx, cancel := context.WithCancel(context.Background())
	if err := s.Start(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { close(h.release) })
	go func() {
		resp, err := http.Get("http://" + s.Addr() + "/metrics")
		if err == nil {
			resp.Body.Close()
		}
	}()
	<-h.entered

	cancel()
	err := s.Wait()
	if err == nil || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Wait after a stuck scrape = %v, want the shutdown deadline error", err)
	}
	if len(logs.ByEvent(logging.EventMetricsServerFailed)) != 1 {
		t.Fatalf("want one metrics.server.failed record, got: %s", logs.Raw())
	}
}
