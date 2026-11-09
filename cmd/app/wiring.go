// Copyright Jetstack Ltd. See LICENSE for details.
package app

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"runtime"
	"slices"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"k8s.io/apiserver/pkg/authentication/authenticator"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/rafpe/kube-oidc-proxy/cmd/app/options"
	"github.com/rafpe/kube-oidc-proxy/pkg/authn"
	"github.com/rafpe/kube-oidc-proxy/pkg/authn/tokenreview"
	"github.com/rafpe/kube-oidc-proxy/pkg/logging"
	"github.com/rafpe/kube-oidc-proxy/pkg/metrics"
	"github.com/rafpe/kube-oidc-proxy/pkg/probe"
	"github.com/rafpe/kube-oidc-proxy/pkg/proxy"
)

// secretFlags names the flags whose values never reach the log stream, not
// even folded into config_hash: the hash is a fingerprint operators compare
// between pods, not a channel for a bearer token. The names are client-go's
// own, which registers the flags (see options.ClientOptions).
var secretFlags = map[string]bool{clientcmd.FlagBearerToken: true}

// configHash fingerprints the effective non-secret configuration so two pods
// can be compared without diffing their flags. Every flag contributes its
// name=value pair, sorted for a stable digest across flag-registration order;
// the SHA-256 is truncated to 16 hex characters, enough to tell two
// configurations apart and short enough to read in a log line.
func configHash(fs *pflag.FlagSet) string {
	var pairs []string
	fs.VisitAll(func(f *pflag.Flag) {
		if secretFlags[f.Name] {
			return
		}
		pairs = append(pairs, f.Name+"="+f.Value.String())
	})
	slices.Sort(pairs)

	sum := sha256.Sum256([]byte(strings.Join(pairs, "\n")))
	return hex.EncodeToString(sum[:])[:configHashLength]
}

// configHashLength is how much of the config digest is logged.
const configHashLength = 16

// configSummary is the effective non-secret configuration the startup record
// reports. It exists so the record's fields are assembled and asserted in one
// place rather than spelled out at the call site.
type configSummary struct {
	version       string
	configHash    string
	issuerCount   int
	readinessMode probe.ReadinessMode
}

// logConfigLoaded reports the effective configuration once it is fixed:
// everything after this point reads it and nothing changes it. config_hash
// lets two pods be compared without diffing their flags.
func logConfigLoaded(l *slog.Logger, summary configSummary) {
	logging.Emit(context.Background(), l, logging.EventProxyConfigLoaded,
		slog.String("version", summary.version),
		slog.String("config_hash", summary.configHash),
		slog.Int("issuer_count", summary.issuerCount),
		slog.String("readiness_mode", string(summary.readinessMode)))
}

// metricsListener is the started metrics listener and the cancel that stops
// it. A nil *metricsListener is the disabled listener: Stop has nothing to do.
type metricsListener struct {
	server *metrics.Server
	cancel context.CancelFunc
}

// Stop stops the listener and waits for its drain, returning the drain's
// terminal error.
func (m *metricsListener) Stop() error {
	if m == nil {
		return nil
	}
	m.cancel()
	return m.server.Wait()
}

// startMetrics builds the recorder and starts the metrics listener when
// metrics are enabled. With metrics disabled both are nil: every collaborator
// treats a nil recorder as a no-op, and a nil listener stops as a no-op.
//
// The listener has a context of its own rather than the one the stop signal
// cancels: it must outlive the readiness listener and the audit flush, which
// report their own failures through the recorder, so a scrape landing in the
// drain window can still see them. Only Stop stops it.
func startMetrics(opts *options.Options, root *slog.Logger) (*metrics.Recorder, *metricsListener, error) {
	if !opts.Metrics.Enabled() {
		return nil, nil, nil
	}
	recorder, err := metrics.New(metrics.BuildInfo{
		Version:   opts.Version.Version(),
		Revision:  opts.Version.Commit(),
		GoVersion: runtime.Version(),
	})
	if err != nil {
		return nil, nil, err
	}
	server := metrics.NewServer(metrics.ServerConfig{
		Addr:     opts.Metrics.BindAddress,
		Recorder: recorder,
	}, logging.ForComponent(root, logging.ComponentMetrics))

	ctx, cancel := context.WithCancel(context.Background())
	if err := server.Start(ctx); err != nil {
		cancel()
		return nil, nil, err
	}
	return recorder, &metricsListener{server: server, cancel: cancel}, nil
}

// buildRESTConfig selects the API server client configuration: the explicit
// client flags when any was given, the in-cluster configuration otherwise,
// with the configured client throttling applied to either.
func buildRESTConfig(opts *options.Options, cmd *cobra.Command) (*rest.Config, error) {
	var restConfig *rest.Config
	var err error
	if opts.Client.ClientFlagsChanged(cmd) {
		restConfig, err = opts.Client.ToRESTConfig()
	} else {
		restConfig, err = rest.InClusterConfig()
	}
	if err != nil {
		return nil, fmt.Errorf("building the API server client configuration: %w", err)
	}

	if opts.Client.KubeClientBurst > 0 {
		restConfig.Burst = opts.Client.KubeClientBurst
	}
	if opts.Client.KubeClientQPS > 0 {
		restConfig.QPS = opts.Client.KubeClientQPS
	}
	return restConfig, nil
}

// buildTokenReviewer builds the token passthrough reviewer, or returns a nil
// reviewer when passthrough is disabled. The reviewer is fronted by a token
// result cache so repeated reviews of the same token (e.g. request storms
// during an OIDC issuer outage) do not each cost an API server round trip.
func buildTokenReviewer(opts *options.Options, kubeclient kubernetes.Interface, recorder *metrics.Recorder, root *slog.Logger) authenticator.Token {
	if !opts.App.TokenPassthrough.Enabled {
		return nil
	}
	return tokenreview.New(kubeclient.AuthenticationV1().TokenReviews(), tokenreview.Config{
		Audiences:       opts.App.TokenPassthrough.Audiences,
		Timeout:         opts.App.TokenPassthrough.Timeout,
		SuccessCacheTTL: opts.App.TokenPassthrough.SuccessCacheTTL,
		FailureCacheTTL: opts.App.TokenPassthrough.FailureCacheTTL,
		Metrics:         recorder,
	}, logging.ForComponent(root, logging.ComponentTokenReview))
}

// proxyConfig maps the parsed flags onto the proxy's configuration.
func proxyConfig(opts *options.Options) proxy.Config {
	return proxy.Config{
		TokenPassthrough:     opts.App.TokenPassthrough.Enabled,
		DisableImpersonation: opts.App.DisableImpersonation,

		FlushInterval: opts.App.FlushInterval,

		ExtraUserHeaders:                opts.App.ExtraHeaders.ExtraUserHeaders,
		ExtraUserHeadersClientIPEnabled: opts.App.ExtraHeaders.ExtraUserHeadersClientIPEnabled,

		TrustedProxies: opts.App.TrustedProxies,

		AllowedReservedGroups: opts.App.AllowedReservedGroups,
	}
}

// authenticatorConfig maps the parsed flags onto the authenticator package's
// configuration, which is the only thing that package needs from the command.
func authenticatorConfig(opts *options.Options) authn.Config {
	o := opts.OIDCAuthentication
	return authn.Config{
		ConfigFile: opts.AuthenticationConfig.ConfigFile,
		Issuer: authn.IssuerConfig{
			URL:            o.IssuerURL,
			ClientID:       o.ClientID,
			CAFile:         o.CAFile,
			UsernameClaim:  o.UsernameClaim,
			UsernamePrefix: o.UsernamePrefix,
			GroupsClaim:    o.GroupsClaim,
			GroupsPrefix:   o.GroupsPrefix,
			SigningAlgs:    o.SigningAlgs,
			RequiredClaims: o.RequiredClaims,
		},
		TLSClientCertFile: o.TLSClientCertFile,
		TLSClientKeyFile:  o.TLSClientKeyFile,
	}
}
