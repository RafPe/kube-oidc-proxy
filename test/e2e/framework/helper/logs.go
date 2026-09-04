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
// so a failing expectation can report the output it was matched against. The
// raw text is returned even on a decode error, so the caller can report the
// stream the error came from.
func (h *Helper) ProxyLogRecords(ns, selector string) ([]map[string]any, string, error) {
	raw, err := h.PodLogs(ns, selector)
	if err != nil {
		return nil, "", err
	}

	records, err := decodeRecords(raw)
	if err != nil {
		return nil, raw, err
	}

	return records, raw, nil
}

// decodeRecords decodes every non-empty line of raw as one JSON object. A line
// that does not decode is an error naming the line number and the line itself,
// never a skip: the proxy's contract is one JSON object per line, and a
// silently dropped line would let a malformed record disappear from every
// assertion made against the decoded set.
func decodeRecords(raw string) ([]map[string]any, error) {
	var records []map[string]any
	for i, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// Declared, not made: unmarshalling JSON null into a map succeeds and
		// leaves it nil rather than erroring, so the nil check below is the
		// only thing that stops a "null" line becoming an empty record.
		var rec map[string]any
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			return nil, fmt.Errorf("line %d is not a JSON object: %s: %w", i+1, bound(line), err)
		}
		if rec == nil {
			return nil, fmt.Errorf("line %d is JSON null, not an object: %s", i+1, bound(line))
		}
		records = append(records, rec)
	}

	return records, nil
}

// maxReportedLine is how much of an undecodable line the error quotes. A single
// record can run to kilobytes (client-go logs a whole curl command at -v=10),
// and the point of the quote is to identify the line, not to reproduce it.
const maxReportedLine = 200

// bound renders a line for an error message, truncated and quoted.
func bound(line string) string {
	if len(line) > maxReportedLine {
		return fmt.Sprintf("%q (truncated from %d bytes)", line[:maxReportedLine], len(line))
	}
	return fmt.Sprintf("%q", line)
}
