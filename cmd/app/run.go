// Copyright Jetstack Ltd. See LICENSE for details.

// Package app assembles the kube-oidc-proxy command: it wires the OIDC
// authenticator, token/subject-access reviewers, readiness probe and proxy
// together and runs them until the supplied stop channel is closed.
package app

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"k8s.io/apiserver/pkg/authentication/authenticator"
	"k8s.io/apiserver/pkg/server"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"github.com/rafpe/kube-oidc-proxy/cmd/app/options"
	"github.com/rafpe/kube-oidc-proxy/pkg/authn"
	"github.com/rafpe/kube-oidc-proxy/pkg/authn/tokenreview"
	"github.com/rafpe/kube-oidc-proxy/pkg/logging"
	"github.com/rafpe/kube-oidc-proxy/pkg/metrics"
	"github.com/rafpe/kube-oidc-proxy/pkg/probe"
	"github.com/rafpe/kube-oidc-proxy/pkg/proxy"
	"github.com/rafpe/kube-oidc-proxy/pkg/proxy/subjectaccessreview"
	"github.com/rafpe/kube-oidc-proxy/pkg/util/signals"
)

// checkReservedIdentityPrefixes refuses to start when the operator's own
// username or group prefix would itself mint reserved identities for every
// authenticated user. It is a startup nicety, not the guard: the runtime check
// in the proxy catches everything this misses, including reserved values that
// arrive in the claim rather than the prefix.
//
// Only the single-issuer path is checked. --oidc-username-prefix and
// --oidc-groups-prefix are ignored entirely when --authentication-config is set,
// where prefixes come from the configuration document instead.
func checkReservedIdentityPrefixes(opts *options.Options) error {
	if opts.AuthenticationConfig.ConfigFile != "" {
		return nil
	}

	for _, prefix := range []struct {
		flag  string
		value string
	}{
		{flag: "--oidc-username-prefix", value: opts.OIDCAuthentication.UsernamePrefix},
		{flag: "--oidc-groups-prefix", value: opts.OIDCAuthentication.GroupsPrefix},
	} {
		if strings.HasPrefix(prefix.value, proxy.ReservedIdentityPrefix) {
			return fmt.Errorf("%s=%q would prefix every authenticated identity with the "+
				"Kubernetes-reserved %q; refusing to start",
				prefix.flag, prefix.value, proxy.ReservedIdentityPrefix)
		}
	}

	return nil
}

// secretFlags names the flags whose values never reach the log stream, not
// even folded into config_hash: the hash is a fingerprint operators compare
// between pods, not a channel for a bearer token.
var secretFlags = map[string]bool{"token": true, "password": true}

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
	sort.Strings(pairs)

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
	readinessMode string
}

// logConfigLoaded reports the effective configuration once it is fixed:
// everything after this point reads it and nothing changes it. config_hash
// lets two pods be compared without diffing their flags.
func logConfigLoaded(l *slog.Logger, summary configSummary) {
	logging.Emit(context.Background(), l, logging.EventProxyConfigLoaded,
		slog.String("version", summary.version),
		slog.String("config_hash", summary.configHash),
		slog.Int("issuer_count", summary.issuerCount),
		slog.String("readiness_mode", summary.readinessMode))
}

// startMetrics builds the recorder and starts the metrics listener when
// metrics are enabled. Both are nil when they are not; every collaborator
// treats a nil recorder as a no-op.
func startMetrics(ctx context.Context, opts *options.Options, root *slog.Logger) (*metrics.Recorder, *metrics.Server, error) {
	if !opts.Metrics.Enabled() {
		return nil, nil, nil
	}
	recorder, err := metrics.New(metrics.BuildInfo{
		Version:   opts.Version.Version(),
		Revision:  opts.Version.Commit(),
		GoVersion: runtime.Version(),
	})
	if err != nil {
		return nil, nil, fmt.Errorf("building the metrics recorder: %w", err)
	}
	server := metrics.NewServer(opts.Metrics.BindAddress, recorder,
		logging.ForComponent(root, logging.ComponentMetrics))
	if err := server.Start(ctx); err != nil {
		return nil, nil, err
	}
	return recorder, server, nil
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

// buildTokenReviewer builds the token passthrough reviewer, or returns nil
// when passthrough is disabled. The reviewer is fronted by a token result
// cache so repeated reviews of the same token (e.g. request storms during an
// OIDC issuer outage) do not each cost an API server round trip.
func buildTokenReviewer(opts *options.Options, kubeclient kubernetes.Interface, recorder *metrics.Recorder, root *slog.Logger) authenticator.Token {
	if !opts.App.TokenPassthrough.Enabled {
		return nil
	}
	return tokenreview.New(kubeclient.AuthenticationV1().TokenReviews(), tokenreview.Config{
		Audiences:       opts.App.TokenPassthrough.Audiences,
		Timeout:         opts.App.TokenPassthrough.RequestTimeout,
		CacheSuccessTTL: opts.App.TokenPassthrough.CacheSuccessTTL,
		CacheFailureTTL: opts.App.TokenPassthrough.CacheFailureTTL,
		Metrics:         recorder,
	}, logging.ForComponent(root, logging.ComponentTokenReview))
}

// proxyConfig maps the parsed flags onto the proxy's configuration.
func proxyConfig(opts *options.Options) *proxy.Config {
	return &proxy.Config{
		TokenReview:          opts.App.TokenPassthrough.Enabled,
		DisableImpersonation: opts.App.DisableImpersonation,

		FlushInterval:   opts.App.FlushInterval,
		ExternalAddress: opts.SecureServing.BindAddress.String(),

		ExtraUserHeaders:                opts.App.ExtraHeaderOptions.ExtraUserHeaders,
		ExtraUserHeadersClientIPEnabled: opts.App.ExtraHeaderOptions.EnableClientIPExtraUserHeader,

		TrustedProxies: opts.App.TrustedProxies,

		AllowedReservedGroups: opts.App.AllowedReservedGroups,
	}
}

// issuerProbes pairs every configured issuer with the fake JWT the readiness
// probe sends it.
func issuerProbes(issuerURLs []string) ([]probe.IssuerReadiness, error) {
	probes := make([]probe.IssuerReadiness, 0, len(issuerURLs))
	for _, issuerURL := range issuerURLs {
		readiness, err := probe.NewIssuerReadiness(issuerURL)
		if err != nil {
			return nil, fmt.Errorf("building the readiness probe for %q: %w", issuerURL, err)
		}
		probes = append(probes, readiness)
	}
	return probes, nil
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

// drain runs the shutdown sequence once the proxy has stopped serving, and
// joins every failure it collects, so a listener that never released its port
// and a hook that could not flush both reach the exit status. No step is
// skipped because an earlier one failed.
//
// The order matters. The readiness listener began stopping when the stop
// signal cancelled its context, so nothing new is admitted; drain waits for it
// first. The proxy's pre-shutdown step runs next; it reports through the
// recorder -- the audit backend increments the operation="shutdown" counter --
// so the metrics listener stops last, and a scrape landing in the drain window
// can still read what it recorded.
//
// stopMetrics stops the metrics listener and waits for it; with the listener
// disabled it is noStep, so every step is always called.
func drain(waitProbe, shutdownProxy, stopMetrics func() error) error {
	probeErr := waitProbe()
	shutdownErr := shutdownProxy()
	metricsErr := stopMetrics()

	return errors.Join(probeErr, shutdownErr, metricsErr)
}

// noStep is the drain step for a listener that was never started.
func noStep() error { return nil }

// ErrReported marks an error that was already emitted on the log stream. main
// exits non-zero on it without printing it again, so a failure after the
// logger exists never adds an unstructured line beside the JSON records.
var ErrReported = errors.New("error already reported on the log stream")

// NewRunCommand builds the root command. The signal handler is installed inside
// RunE rather than by the caller, because the shutdown logger it reports
// through is derived from the root logger, which cannot exist until the
// command line has been parsed.
func NewRunCommand() *cobra.Command {
	opts := options.New()
	cmd := buildRunCommand(opts, os.Stdout)
	opts.AddFlags(cmd)

	return cmd
}

// buildRunCommand builds the proxy command writing its log stream to out, which
// is stdout in production and a buffer under test.
func buildRunCommand(opts *options.Options, out io.Writer) *cobra.Command {
	return &cobra.Command{
		Use:  options.AppName,
		Long: "kube-oidc-proxy is a reverse proxy to authenticate users to Kubernetes API servers with Open ID Connect Authentication.",
		// The process reports its own errors: on the log stream once the logger
		// exists, through main before that. cobra's own error and usage output
		// would be a second, unstructured copy.
		SilenceErrors: true,
		SilenceUsage:  true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if opts.Version.Requested(cmd) {
				opts.Version.PrintVersionAndExit()
			}
			if err := opts.Validate(cmd); err != nil {
				return err
			}

			// One root logger for the whole process, built from the flags and
			// injected into every collaborator below; no package holds its own.
			root, err := logging.New(opts.Logging.ToLoggerOptions(out))
			if err != nil {
				return err
			}
			slog.SetDefault(root)

			// From here on every failure is a record on the configured stream,
			// and the returned error only carries the exit status.
			startupLogger := logging.ForComponent(root, logging.ComponentStartup)
			fail := func(err error) error {
				logging.Emit(context.Background(), startupLogger, logging.EventProxyStartupFailed, logging.ErrAttr(err))
				return fmt.Errorf("%w: %w", ErrReported, err)
			}

			// Kubernetes libraries log through klog; route them into the same
			// stream under component=k8s rather than leaving a second format
			// on stderr.
			logging.InstallKlogBridge(root, opts.Logging.Verbosity())

			// Trap SIGINT/SIGTERM only once the root logger exists, so shutdown
			// reports through the configured stream. Nothing is serving before
			// this point, so a signal that arrives earlier ends the process
			// with Go's default behaviour.
			stopCh := signals.NotifyStop(logging.ForComponent(root, logging.ComponentShutdown))

			// Derive a context cancelled when the app stop signal fires, giving the
			// metrics and readiness servers an explicit shutdown path.
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			go func() {
				select {
				case <-stopCh:
					cancel()
				case <-ctx.Done():
				}
			}()

			// The metrics listener has no dependencies, so it starts first: a
			// port-in-use failure is then the first thing reported, and a scrape
			// that arrives before readiness sees build_info and the runtime
			// collectors, as it does on any Kubernetes component. recorder stays
			// nil when metrics are disabled; every collaborator treats a nil
			// recorder as a no-op.
			// The metrics listener has a context of its own rather than the
			// shared one: it must outlive the readiness listener and the
			// pre-shutdown hooks, which report their own failures through the
			// recorder, so a scrape landing in the drain window can still see
			// them. drain below cancels it once the hooks have returned.
			metricsCtx, cancelMetrics := context.WithCancel(context.Background())
			defer cancelMetrics()

			recorder, metricsServer, err := startMetrics(metricsCtx, opts, root)
			if err != nil {
				return fail(err)
			}
			if metricsServer != nil {
				defer func() {
					cancelMetrics()
					// Reported as metrics.server.failed by the server itself;
					// on a startup failure the exit status already says so.
					_ = metricsServer.Wait()
				}()
			}

			if err := checkReservedIdentityPrefixes(opts); err != nil {
				return fail(err)
			}

			restConfig, err := buildRESTConfig(opts, cmd)
			if err != nil {
				return fail(err)
			}

			// One client serves both reviewers' API calls.
			kubeclient, err := kubernetes.NewForConfig(restConfig)
			if err != nil {
				return fail(fmt.Errorf("building the API server client: %w", err))
			}

			secureServingInfo := new(server.SecureServingInfo)
			if err := opts.SecureServing.ApplyTo(&secureServingInfo); err != nil {
				return fail(err)
			}

			subjectAccessReviewer, err := subjectaccessreview.New(
				kubeclient.AuthorizationV1().SubjectAccessReviews(),
				subjectaccessreview.Config{
					Timeout:         opts.App.SubjectAccessReviewTimeout,
					AllowCacheTTL:   opts.App.SubjectAccessReviewAllowCacheTTL,
					DenyCacheTTL:    opts.App.SubjectAccessReviewDenyCacheTTL,
					MaxHeaderValues: opts.App.MaxImpersonationHeaderValues,
					Metrics:         recorder,
				},
				logging.ForComponent(root, logging.ComponentSAR),
			)
			if err != nil {
				return fail(err)
			}

			tokenAuthenticator, issuerURLs, err := authn.Build(authenticatorConfig(opts),
				logging.ForComponent(root, logging.ComponentOIDC), startupLogger)
			if err != nil {
				return fail(err)
			}

			p, err := proxy.New(proxy.Dependencies{
				Logger:                 root,
				RestConfig:             restConfig,
				OIDCTokenAuthenticator: tokenAuthenticator,
				AuditOptions:           opts.Audit,
				TokenReviewer:          buildTokenReviewer(opts, kubeclient, recorder, root),
				SubjectAccessReviewer:  subjectAccessReviewer,
				SecureServingInfo:      secureServingInfo,
				Config:                 proxyConfig(opts),
				Metrics:                recorder,
			})
			if err != nil {
				return fail(err)
			}

			logConfigLoaded(startupLogger, configSummary{
				version:       opts.Version.Version(),
				configHash:    configHash(cmd.Flags()),
				issuerCount:   len(issuerURLs),
				readinessMode: probe.ReadinessMode(opts.App.ReadinessRequireAllIssuers),
			})

			probes, err := issuerProbes(issuerURLs)
			if err != nil {
				return fail(err)
			}

			// Start binds synchronously so a port-in-use failure surfaces here
			// at startup.
			probeServer := probe.NewServer(probe.Config{
				// The kubelet probes the pod IP, so the listener binds every
				// interface.
				Addr:              net.JoinHostPort("0.0.0.0", strconv.Itoa(opts.App.ReadinessProbePort)),
				Issuers:           probes,
				RequireAllIssuers: opts.App.ReadinessRequireAllIssuers,
				Authenticator:     tokenAuthenticator,
				Metrics:           recorder,
			}, root)
			if err := probeServer.Start(ctx); err != nil {
				return fail(err)
			}

			if err := p.Start(ctx); err != nil {
				return fail(err)
			}
			servingSince := time.Now()

			serverLogger := logging.ForComponent(root, logging.ComponentServer)
			logging.Emit(context.Background(), serverLogger, logging.EventProxyServerStarted,
				slog.String("address", net.JoinHostPort(opts.SecureServing.BindAddress.String(),
					strconv.Itoa(opts.SecureServing.BindPort))))

			// The handler chain is built and the secure server is serving its
			// listener. Only now may the pod be advertised as ready: the port
			// has been bound since SecureServing.ApplyTo above, so before this
			// point a client connect succeeds and then sits in the backlog
			// unanswered, and a failure in Start would leave it that way.
			probeServer.SetServing()

			p.Wait()

			logging.Emit(context.Background(), serverLogger, logging.EventProxyServerStopped,
				slog.Int64("duration_ms", time.Since(servingSince).Milliseconds()))

			// Wait for the listeners to release their ports and run the
			// pre-shutdown step. Errors are collected, not returned: every step
			// runs whatever the previous one reported. Each failure was already
			// named on the log stream by its owner.
			shutdownSince := time.Now()
			stopMetrics := noStep
			if metricsServer != nil {
				stopMetrics = func() error { cancelMetrics(); return metricsServer.Wait() }
			}
			drainErr := drain(probeServer.Wait, p.Shutdown, stopMetrics)

			// Reported whether or not a hook failed: the milestone is that the
			// teardown finished, and the failing hook has already named itself.
			logging.Emit(context.Background(), logging.ForComponent(root, logging.ComponentShutdown),
				logging.EventProxyShutdownCompleted,
				slog.Int64("duration_ms", time.Since(shutdownSince).Milliseconds()))

			if err := drainErr; err != nil {
				// Each failure was reported on the stream by its owner.
				return fmt.Errorf("%w: %w", ErrReported, err)
			}
			return nil
		},
	}
}
