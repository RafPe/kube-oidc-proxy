// Copyright Jetstack Ltd. See LICENSE for details.
package logging_test

import (
	"errors"
	"testing"

	"k8s.io/klog/v2"

	"github.com/rafpe/kube-oidc-proxy/pkg/logging"
	"github.com/rafpe/kube-oidc-proxy/pkg/logging/logtest"
)

func TestBridgeMapsKlogVerbosityToDebugAndTagsComponent(t *testing.T) {
	root, cap := logtest.New(t, 2)
	logging.InstallKlogBridge(root, 2)
	t.Cleanup(func() { klog.ClearLogger() })

	klog.V(2).InfoS("throttled", "delay", "1s")
	klog.V(4).InfoS("too verbose for -v=2")
	klog.ErrorS(errors.New("boom"), "failed")
	klog.Infof("printf %s", "style")
	klog.Flush()

	recs := cap.Records()
	byMsg := map[string]logtest.Record{}
	for _, r := range recs {
		byMsg[r.String("msg")] = r
		if r.String("component") != "k8s" {
			t.Errorf("bridged record without component=k8s: %v", r)
		}
		if _, has := r["event_type"]; has {
			t.Errorf("bridged record carries event_type: %v", r)
		}
	}
	if byMsg["throttled"].String("level") != "DEBUG" || byMsg["throttled"].String("delay") != "1s" {
		t.Errorf("V(2) record: %v", byMsg["throttled"])
	}
	if _, has := byMsg["too verbose for -v=2"]; has {
		t.Error("V(4) record passed a -v=2 bridge")
	}
	if byMsg["failed"].String("level") != "ERROR" {
		t.Errorf("ErrorS record: %v", byMsg["failed"])
	}
	if byMsg["printf style"].String("level") != "INFO" {
		t.Errorf("Infof record: %v", byMsg["printf style"])
	}
}
