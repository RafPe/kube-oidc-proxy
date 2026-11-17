// Copyright Jetstack Ltd. See LICENSE for details.

//go:build !logcheck

package logging

import (
	"context"
	"log/slog"
	"testing"
)

// TestCheckRequiredIsANoOpInOrdinaryBuilds pins the production half of the
// build-tag pair: without -tags logcheck a record missing a required
// attribute is emitted rather than panicking, so the check costs nothing and
// can never take a serving proxy down.
func TestCheckRequiredIsANoOpInOrdinaryBuilds(t *testing.T) {
	spec, ok := EventRequestAccessDecided.Spec()
	if !ok || len(spec.Required) == 0 {
		t.Fatal("test needs an event with required attributes")
	}
	checkRequired(EventRequestAccessDecided, spec, nil)

	// The whole path: Emit with none of the required attributes.
	Emit(context.Background(), slog.New(slog.DiscardHandler), EventRequestAccessDecided)
}
