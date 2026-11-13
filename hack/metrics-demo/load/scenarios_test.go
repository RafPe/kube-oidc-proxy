// Copyright Jetstack Ltd. See LICENSE for details.
package main

import (
	"errors"
	"testing"
)

func TestResultOKRequiresTheWantedStatus(t *testing.T) {
	if !(result{status: 200, want: 200}).ok() {
		t.Error("matching status is not ok")
	}
	if (result{status: 403, want: 200}).ok() {
		t.Error("mismatched status is ok")
	}
	if (result{status: 200, want: 200, err: errors.New("boom")}).ok() {
		t.Error("an error is ok")
	}
	if got := failed("kind", errors.New("boom")); len(got) != 1 || got[0].kind != "kind" || got[0].err == nil {
		t.Errorf("failed() = %+v", got)
	}
}
