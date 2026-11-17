// Copyright Jetstack Ltd. See LICENSE for details.
package ctxerr

import (
	"context"
	"errors"
	"fmt"
	"testing"
)

func TestIs(t *testing.T) {
	tests := map[string]struct {
		err  error
		want bool
	}{
		"cancellation":      {context.Canceled, true},
		"deadline":          {context.DeadlineExceeded, true},
		"wrapped deadline":  {fmt.Errorf("review: %w", context.DeadlineExceeded), true},
		"non-context error": {errors.New("apiserver 500"), false},
		"nil":               {nil, false},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			if got := Is(tc.err); got != tc.want {
				t.Errorf("Is = %t, want %t", got, tc.want)
			}
		})
	}
}

func TestClientGone(t *testing.T) {
	live := context.Background()
	ended, cancel := context.WithCancel(context.Background())
	cancel()

	tests := map[string]struct {
		ctx  context.Context
		err  error
		want bool
	}{
		"request ended, cancellation":      {ended, context.Canceled, true},
		"request ended, wrapped deadline":  {ended, fmt.Errorf("review: %w", context.DeadlineExceeded), true},
		"request ended, non-context error": {ended, errors.New("apiserver 500"), false},
		"request live, cancellation":       {live, context.Canceled, false},
		"request live, deadline":           {live, context.DeadlineExceeded, false},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			if got := ClientGone(tc.ctx, tc.err); got != tc.want {
				t.Errorf("ClientGone = %t, want %t", got, tc.want)
			}
		})
	}
}
