// Copyright Jetstack Ltd. See LICENSE for details.

//go:build logcheck

// The required-attribute assertions only exist under -tags logcheck, the tag
// the Makefile and CI set, so the tests that prove they fire live here rather
// than in logger_test.go. An untagged `go test ./pkg/logging/...` then stays
// green for anyone running it by hand.
package logging_test

import (
	"context"
	"log/slog"
	"testing"

	"github.com/rafpe/kube-oidc-proxy/pkg/logging"
	"github.com/rafpe/kube-oidc-proxy/pkg/logging/logtest"
)

func TestEmitPanicsOnMissingRequiredFieldUnderLogcheck(t *testing.T) {
	root, _ := logtest.New(t, 0)
	defer func() {
		if recover() == nil {
			t.Fatal("Emit did not panic on a missing required field with -tags logcheck")
		}
	}()
	logging.Emit(context.Background(), root, logging.EventProxyServerStarted) // address missing
}

func TestEmitPanicsWhenRequestIDIsNeitherPassedNorInContext(t *testing.T) {
	root, _ := logtest.New(t, 2)
	defer func() {
		if recover() == nil {
			t.Fatal("Emit did not panic on a required request_id absent from both the attrs and the context")
		}
	}()
	logging.Emit(context.Background(), root, logging.EventCacheSARLookup, slog.String("cache_result", "hit"))
}
