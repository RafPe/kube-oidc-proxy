// Copyright Jetstack Ltd. See LICENSE for details.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/rafpe/kube-oidc-proxy/pkg/util/signals"
	"github.com/rafpe/kube-oidc-proxy/test/tools/echoserver/pkg/echo"
)

func main() {
	addr := flag.String("listen", ":8080", "Address to serve HTTP on.")
	flag.Parse()

	stopCh := signals.Handler(slog.Default())

	srv := &http.Server{
		Addr:              *addr,
		Handler:           echo.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	go func() {
		<-stopCh
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	}()

	slog.Info("echo server listening", "addr", *addr)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		os.Exit(1)
	}
}
