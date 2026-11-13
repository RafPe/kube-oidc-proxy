// Copyright Jetstack Ltd. See LICENSE for details.
package proxy

import (
	"fmt"
	"os"
	"sync"
	"testing"

	"github.com/rafpe/kube-oidc-proxy/pkg/logging/logtest"
)

// sweep collects every capture a test in this package built through
// newTestProxy. Holding them all at the end catches an unregistered event, a
// wrong component or level and a missing required attribute in whatever record
// any test happened to produce, without every test having to assert it.
var sweep struct {
	mu       sync.Mutex
	captures []*logtest.Capture
}

// trackCapture adds a capture to the package sweep. It is called from
// newTestProxy, so tests running in parallel append concurrently.
func trackCapture(c *logtest.Capture) {
	sweep.mu.Lock()
	defer sweep.mu.Unlock()
	sweep.captures = append(sweep.captures, c)
}

// TestMain runs the package's tests and then holds every record they emitted
// against the event registry. It runs after m.Run so the captures are complete.
func TestMain(m *testing.M) {
	code := m.Run()

	tb := new(sweepTB)
	sweep.mu.Lock()
	for _, c := range sweep.captures {
		logtest.AssertRegistered(tb, c)
	}
	sweep.mu.Unlock()

	if tb.failed && code == 0 {
		code = 1
	}
	os.Exit(code)
}

// sweepTB is the testing.TB AssertRegistered reports through when there is no
// *testing.T to report through, which is the case inside TestMain. The
// embedded interface stays nil: every method the assertion uses is overridden
// below, and a call to any other one is a programming error worth the panic.
type sweepTB struct {
	testing.TB
	failed bool
}

func (s *sweepTB) Helper() {}

func (s *sweepTB) Errorf(format string, args ...any) {
	s.failed = true
	fmt.Fprintf(os.Stderr, "events sweep: "+format+"\n", args...)
}

func (s *sweepTB) Error(args ...any) {
	s.Errorf("%s", fmt.Sprint(args...))
}

func (s *sweepTB) Fatalf(format string, args ...any) {
	s.Errorf(format, args...)
}

func (s *sweepTB) Fatal(args ...any) {
	s.Error(args...)
}
