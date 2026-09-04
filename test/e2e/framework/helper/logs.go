// Copyright Jetstack Ltd. See LICENSE for details.
package helper

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// PodLogs returns the logs of the single pod matching selector in ns. A pod
// with more than one container is read through the container named by its app
// label, which is how deployApp names both.
func (h *Helper) PodLogs(ns, selector string) (string, error) {
	pods, err := h.KubeClient.CoreV1().Pods(ns).List(context.TODO(),
		metav1.ListOptions{LabelSelector: selector})
	if err != nil {
		return "", err
	}
	if len(pods.Items) != 1 {
		return "", fmt.Errorf("expected a single pod matching %q in %s, got=%d", selector, ns, len(pods.Items))
	}

	pod := pods.Items[0]
	opts := new(corev1.PodLogOptions)
	if len(pod.Spec.Containers) > 1 {
		opts.Container = pod.Labels["app"]
	}

	logs, err := h.KubeClient.CoreV1().Pods(ns).GetLogs(pod.Name, opts).DoRaw(context.TODO())
	if err != nil {
		return "", err
	}

	return string(logs), nil
}

// ProxyLogRecords returns the structured records the proxy has written, decoded
// one per line, together with the raw log text. The raw text is returned
// alongside so a caller can assert on what the stream does *not* contain, and
// so a failing expectation can report the output it was matched against.
//
// Lines that are not a JSON object are skipped rather than reported as an
// error: the decoded records and the raw text are two separate assertions, and
// a caller checking that every line is JSON needs the raw text to say which one
// was not.
func (h *Helper) ProxyLogRecords(ns, selector string) ([]map[string]any, string, error) {
	raw, err := h.PodLogs(ns, selector)
	if err != nil {
		return nil, "", err
	}

	var records []map[string]any
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "{") {
			continue
		}

		rec := make(map[string]any)
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			continue
		}
		records = append(records, rec)
	}

	return records, raw, nil
}
