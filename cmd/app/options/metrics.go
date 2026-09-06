// Copyright Jetstack Ltd. See LICENSE for details.
package options

import (
	"fmt"
	"net"
	"strconv"

	"github.com/spf13/pflag"
	cliflag "k8s.io/component-base/cli/flag"
)

// MetricsOptions configures the optional Prometheus metrics listener.
type MetricsOptions struct {
	// BindAddress is the host:port the metrics listener binds to. Empty and
	// "0" both mean disabled, so an empty chart value renders no flag and the
	// kubebuilder convention of "0" is honoured too.
	BindAddress string
}

func NewMetricsOptions(nfs *cliflag.NamedFlagSets) *MetricsOptions {
	return new(MetricsOptions).AddFlags(nfs.FlagSet("Metrics"))
}

func (m *MetricsOptions) AddFlags(fs *pflag.FlagSet) *MetricsOptions {
	fs.StringVar(&m.BindAddress, "metrics-bind-address", "",
		"Address (host:port) to serve Prometheus metrics on, over plain HTTP at "+
			"GET /metrics. Empty (the default) or \"0\" disables the listener. The "+
			"endpoint reveals traffic shape and health, never identities; restrict "+
			"who can reach it with a NetworkPolicy. Use \"127.0.0.1:<port>\" when a "+
			"sidecar does the scraping. Port 0 is not accepted: the chart and a "+
			"ServiceMonitor must know the port. Must differ from --secure-port and "+
			"--readiness-probe-port.")
	return m
}

// Enabled reports whether a metrics listener is configured.
func (m *MetricsOptions) Enabled() bool {
	return m.BindAddress != "" && m.BindAddress != "0"
}

// Port returns the port part of BindAddress. It is only meaningful when
// Enabled; Validate reports the errors it returns.
func (m *MetricsOptions) Port() (int, error) {
	_, portText, err := net.SplitHostPort(m.BindAddress)
	if err != nil {
		return 0, fmt.Errorf("--metrics-bind-address must be host:port, got %q: %w", m.BindAddress, err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return 0, fmt.Errorf("--metrics-bind-address port must be a number between 1 and 65535, got %q", portText)
	}
	return port, nil
}

// Validate checks the address when the listener is enabled. A disabled
// listener is always valid.
func (m *MetricsOptions) Validate() error {
	if !m.Enabled() {
		return nil
	}
	_, err := m.Port()
	return err
}
