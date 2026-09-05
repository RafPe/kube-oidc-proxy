// Copyright Jetstack Ltd. See LICENSE for details.

//go:build !logcheck

package logging

import "log/slog"

// checkRequired is a no-op in ordinary builds; see logcheck.go for the
// checking implementation compiled under -tags logcheck.
func checkRequired(_ EventType, _ EventSpec, _ []slog.Attr) {}
