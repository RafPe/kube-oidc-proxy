// Copyright Jetstack Ltd. See LICENSE for details.
package httpserve

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
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

// TestNewHTTPServerIsHardened pins the limits every auxiliary listener gets: a
// zero here would be an unbounded read, write or idle period on a port
// anything in the cluster can dial.
func TestNewHTTPServerIsHardened(t *testing.T) {
	srv := NewHTTPServer("127.0.0.1:0", http.NotFoundHandler(), slog.New(slog.DiscardHandler))
	if srv.ReadHeaderTimeout <= 0 || srv.ReadTimeout <= 0 || srv.WriteTimeout != WriteTimeout ||
		srv.IdleTimeout <= 0 || srv.MaxHeaderBytes <= 0 {
		t.Fatalf("server limits not all set: %+v", srv)
	}
}

// TestNewHTTPServerReportsThroughTheLogger pins where net/http's own reports
// about the listener go: to the owner's logger at ERROR, never to the standard
// log package, which would put an unstructured line beside the log stream.
func TestNewHTTPServerReportsThroughTheLogger(t *testing.T) {
	var out bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&out, nil)).With(slog.String("component", "metrics"))
	srv := NewHTTPServer("127.0.0.1:0", http.NotFoundHandler(), logger)

	srv.ErrorLog.Print("http: panic serving 10.0.0.1:1234: boom")

	var rec map[string]any
	if err := json.Unmarshal(out.Bytes(), &rec); err != nil {
		t.Fatalf("ErrorLog output is not one JSON record: %q", out.String())
	}
	if rec["level"] != "ERROR" || rec["component"] != "metrics" ||
		!strings.Contains(fmt.Sprint(rec["msg"]), "panic serving") {
		t.Fatalf("ErrorLog record = %v, want an ERROR record under the owner's component", rec)
	}
}
