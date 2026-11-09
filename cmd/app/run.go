// Copyright Jetstack Ltd. See LICENSE for details.

// Package app assembles the kube-oidc-proxy command: it wires the OIDC
// authenticator, token/subject-access reviewers, readiness probe and proxy
// together and runs them until SIGINT or SIGTERM starts a graceful shutdown.
package app

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"strconv"
	"time"

	"github.com/spf13/cobra"
	"k8s.io/apiserver/pkg/server"
	"k8s.io/client-go/kubernetes"

	"github.com/rafpe/kube-oidc-proxy/cmd/app/options"
	"github.com/rafpe/kube-oidc-proxy/pkg/authn"
	"github.com/rafpe/kube-oidc-proxy/pkg/authz/subjectaccessreview"
	"github.com/rafpe/kube-oidc-proxy/pkg/logging"
	"github.com/rafpe/kube-oidc-proxy/pkg/metrics"
	"github.com/rafpe/kube-oidc-proxy/pkg/probe"
	"github.com/rafpe/kube-oidc-proxy/pkg/proxy"
	"github.com/rafpe/kube-oidc-proxy/pkg/proxy/audit"
	"github.com/rafpe/kube-oidc-proxy/pkg/util/signals"
)

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
	cmd := buildRunCommand(opts, os.Stdout, signals.NotifyStop)
	opts.AddFlags(cmd)

	return cmd
}

// buildRunCommand builds the proxy command writing its log stream to out, which
// is stdout in production and a buffer under test. notifyStop installs the
// stop trigger: signals.NotifyStop in production, a channel the test closes
// under test, so a test never signals its own process.
func buildRunCommand(opts *options.Options, out io.Writer, notifyStop func(*slog.Logger) <-chan struct{}) *cobra.Command {
	return &cobra.Command{
		Use:  options.AppName,
		Long: "kube-oidc-proxy is a reverse proxy to authenticate users to Kubernetes API servers with Open ID Connect Authentication.",
		// The process reports its own errors: on the log stream once the logger
		// exists, through main before that. cobra's own error and usage output
		// would be a second, unstructured copy.
		SilenceErrors: true,
		SilenceUsage:  true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return run(cmd, opts, out, notifyStop)
		},
	}
}

// run is the command body. It builds the root logger and the stop trigger,
// then runs the proxy through its three phases: startup, serve and shutdown.
func run(cmd *cobra.Command, opts *options.Options, out io.Writer, notifyStop func(*slog.Logger) <-chan struct{}) error {
	if opts.Version.Requested() {
		opts.Version.PrintVersionAndExit()
	}
	if err := opts.Validate(cmd); err != nil {
		return err
	}

	// One root logger for the whole process, built from the flags and
	// injected into every collaborator; no package holds its own.
	root, err := logging.New(opts.Logging.ToLoggerOptions(out))
	if err != nil {
		return err
	}

	// Also make root the process default. This binary's own code never reads
	// slog.Default; the reason is the standard log package, which SetDefault
	// redirects into root's handler. Library code this binary cannot hand a
	// logger still writes there -- net/http's client Transport reports an
	// unsolicited response on an idle connection, and a failure to enable
	// HTTP/2, through log.Printf -- and each such line would otherwise be
	// unstructured text on stderr beside the JSON stream.
	slog.SetDefault(root)

	// From here on every failure is a record on the configured stream, and the
	// returned error only carries the exit status.
	fail := func(err error) error {
		logging.Emit(context.Background(), logging.ForComponent(root, logging.ComponentStartup),
			logging.EventProxyStartupFailed, logging.ErrAttr(err))
		return fmt.Errorf("%w: %w", ErrReported, err)
	}

	// Kubernetes libraries log through klog; route them into the same stream
	// under component=k8s rather than leaving a second format on stderr.
	logging.InstallKlogBridge(root, opts.Logging.Verbosity())

	// Trap SIGINT/SIGTERM only once the root logger exists, so shutdown
	// reports through the configured stream. Nothing is serving before this
	// point, so a signal that arrives earlier ends the process with Go's
	// default behaviour. The readiness and proxy listeners stop when ctx does.
	stopCh := notifyStop(logging.ForComponent(root, logging.ComponentShutdown))
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
	// port-in-use failure is then the first thing reported, and a scrape that
	// arrives before readiness sees build_info and the runtime collectors, as
	// it does on any Kubernetes component.
	recorder, metricsListener, err := startMetrics(opts, root)
	if err != nil {
		return fail(err)
	}

	started, err := startup(ctx, cmd, opts, root, recorder)
	if err != nil {
		// A listener that overran its drain is reported as
		// metrics.server.failed by the server itself, and the exit status
		// already says startup failed.
		_ = metricsListener.Stop()
		return fail(err)
	}

	serve(root, opts, started)

	// Each failure was already reported on the stream by its owner.
	if err := shutdown(root, started.probe, started.auditor, metricsListener); err != nil {
		return fmt.Errorf("%w: %w", ErrReported, err)
	}
	return nil
}

// running is what startup hands to serve and shutdown: the started proxy and
// readiness listener, and the auditor shutdown flushes once the proxy has
// stopped serving.
type running struct {
	proxy   *proxy.Proxy
	probe   *probe.Server
	auditor *audit.Audit
}

// startup builds the proxy and its collaborators from the flags, reports the
// effective configuration, and starts the audit backend and the readiness and
// proxy listeners, all of which stop when ctx is cancelled. Neither listener
// reports ready yet: serve does that.
//
// A function from this repository names its own package in the errors it
// returns ("audit: ...", "probe: ..."), so those are returned as they are. A
// third-party failure, such as building the client or binding the secure
// port, is wrapped here with what was being done.
func startup(ctx context.Context, cmd *cobra.Command, opts *options.Options, root *slog.Logger, recorder *metrics.Recorder) (*running, error) {
	startupLogger := logging.ForComponent(root, logging.ComponentStartup)

	restConfig, err := buildRESTConfig(opts, cmd)
	if err != nil {
		return nil, err
	}

	// One client serves both reviewers' API calls.
	kubeclient, err := kubernetes.NewForConfig(restConfig)
	if err != nil {
		return nil, fmt.Errorf("building the API server client: %w", err)
	}

	secureServingInfo := new(server.SecureServingInfo)
	if err := opts.SecureServing.ApplyTo(&secureServingInfo); err != nil {
		return nil, fmt.Errorf("setting up secure serving: %w", err)
	}

	impersonationAuthorizer := subjectaccessreview.New(
		kubeclient.AuthorizationV1().SubjectAccessReviews(),
		subjectaccessreview.Config{
			Timeout:         opts.App.SubjectAccessReview.Timeout,
			AllowCacheTTL:   opts.App.SubjectAccessReview.AllowCacheTTL,
			DenyCacheTTL:    opts.App.SubjectAccessReview.DenyCacheTTL,
			MaxHeaderValues: opts.App.MaxImpersonationHeaderValues,
			Metrics:         recorder,
		},
		logging.ForComponent(root, logging.ComponentSAR),
	)

	tokenAuthenticator, issuerURLs, err := authn.Build(authenticatorConfig(opts), root)
	if err != nil {
		return nil, err
	}

	auditor, err := audit.New(audit.Config{
		Options:         opts.Audit,
		ExternalAddress: opts.SecureServing.BindAddress.String(),
		SecureServing:   secureServingInfo,
		Metrics:         recorder,
	}, logging.ForComponent(root, logging.ComponentAudit))
	if err != nil {
		return nil, err
	}

	tokenReviewer := buildTokenReviewer(opts, kubeclient, recorder, root)

	p, err := proxy.New(proxyConfig(opts), proxy.Dependencies{
		RestConfig:              restConfig,
		OIDCTokenAuthenticator:  tokenAuthenticator,
		Auditor:                 auditor,
		TokenReviewer:           tokenReviewer,
		ImpersonationAuthorizer: impersonationAuthorizer,
		SecureServingInfo:       secureServingInfo,
		Metrics:                 recorder,
	}, root)
	if err != nil {
		return nil, err
	}

	readinessMode := probe.ReadinessModeFor(opts.App.ReadinessRequireAllIssuers)
	logConfigLoaded(startupLogger, configSummary{
		version:       opts.Version.Version(),
		configHash:    configHash(cmd.Flags()),
		issuerCount:   len(issuerURLs),
		readinessMode: readinessMode,
	})

	probeServer := probe.NewServer(probe.Config{
		// The kubelet probes the pod IP, so the listener binds every
		// interface.
		Addr:          net.JoinHostPort("0.0.0.0", strconv.Itoa(opts.App.ReadinessProbePort)),
		IssuerURLs:    issuerURLs,
		Mode:          readinessMode,
		Authenticator: tokenAuthenticator,
		Metrics:       recorder,
	}, root)
	if err := probeServer.Start(ctx); err != nil {
		return nil, err
	}

	if err := auditor.Start(ctx); err != nil {
		return nil, err
	}
	if err := p.Start(ctx); err != nil {
		return nil, err
	}
	return &running{proxy: p, probe: probeServer, auditor: auditor}, nil
}

// serve reports the proxy as serving, lets readiness pass, and blocks until
// the proxy has stopped serving.
//
// proxy.server.started is the one started record cmd/app owns. Every other
// listener's Start reports its own bind (metrics.server.started,
// audit.backend.started), but the proxy's port is bound by apiserver's
// SecureServingInfo during startup and served by apiserver's machinery, so
// proxy.Start never sees a bind of its own to report.
func serve(root *slog.Logger, opts *options.Options, r *running) {
	servingSince := time.Now()
	serverLogger := logging.ForComponent(root, logging.ComponentServer)
	logging.Emit(context.Background(), serverLogger, logging.EventProxyServerStarted,
		slog.String("address", net.JoinHostPort(opts.SecureServing.BindAddress.String(),
			strconv.Itoa(opts.SecureServing.BindPort))))

	// The handler chain is built and the secure server is serving its
	// listener. Only now may the pod be advertised as ready: the port has been
	// bound since SecureServing.ApplyTo, so before this point a client connect
	// succeeds and then sits in the backlog unanswered, and a failure in Start
	// would leave it that way.
	r.probe.SetServing()

	r.proxy.Wait()

	logging.Emit(context.Background(), serverLogger, logging.EventProxyServerStopped,
		slog.Int64("duration_ms", time.Since(servingSince).Milliseconds()))
}
