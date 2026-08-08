// Copyright Jetstack Ltd. See LICENSE for details.

// Package signals installs OS signal handling for graceful shutdown. It maps
// SIGINT/SIGTERM onto a stop channel that callers can wait on to begin an
// orderly teardown.
package signals

import (
	"os"
	"os/signal"
	"syscall"

	"k8s.io/klog/v2"
)

// Handler installs a SIGINT/SIGTERM handler and returns a stop channel that is
// closed on the first such signal, requesting a graceful shutdown. Each
// subsequent signal (up to three) re-logs that shutdown is in progress; the
// next one after that forces an immediate os.Exit(1). Handler is intended to be
// called once during process startup.
func Handler() chan struct{} {
	stopCh := make(chan struct{})
	ch := make(chan os.Signal, 2)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		sig := <-ch

		close(stopCh)

		for i := 0; i < 3; i++ {
			klog.V(0).Infof("received signal %s, shutting down gracefully...", sig)
			sig = <-ch
		}

		klog.V(0).Infof("received signal %s, force closing", sig)

		os.Exit(1)
	}()

	return stopCh
}
