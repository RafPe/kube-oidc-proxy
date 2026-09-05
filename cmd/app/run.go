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
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	apiserverapi "k8s.io/apiserver/pkg/apis/apiserver"
	"k8s.io/apiserver/pkg/authentication/authenticator"
	authenticationcel "k8s.io/apiserver/pkg/authentication/cel"
	tokenunion "k8s.io/apiserver/pkg/authentication/token/union"
	"k8s.io/apiserver/pkg/server"
	"k8s.io/apiserver/pkg/server/dynamiccertificates"
	"k8s.io/apiserver/plugin/pkg/authenticator/token/oidc"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"github.com/rafpe/kube-oidc-proxy/cmd/app/options"
	"github.com/rafpe/kube-oidc-proxy/pkg/logging"
	"github.com/rafpe/kube-oidc-proxy/pkg/probe"
	"github.com/rafpe/kube-oidc-proxy/pkg/proxy"
	"github.com/rafpe/kube-oidc-proxy/pkg/proxy/subjectaccessreview"
	"github.com/rafpe/kube-oidc-proxy/pkg/proxy/tokenreview"
	"github.com/rafpe/kube-oidc-proxy/pkg/util/signals"
	"github.com/rafpe/kube-oidc-proxy/pkg/util/token"
)

const oidcHTTPTimeout = 30 * time.Second

// reservedIdentityPrefix is the username/group prefix Kubernetes reserves for
// its own identities. Kept in sync with the runtime guard in
// pkg/proxy/handlers.go (checkReservedIdentity), which is the load-bearing one.
const reservedIdentityPrefix = "system:"

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
		if strings.HasPrefix(prefix.value, reservedIdentityPrefix) {
			return fmt.Errorf("%s=%q would prefix every authenticated identity with the "+
				"Kubernetes-reserved %q; refusing to start",
				prefix.flag, prefix.value, reservedIdentityPrefix)
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

// logIssuersConfigured reports one record per configured issuer, so a query on
// oidc.issuer.configured lists what this pod accepts without decomposing a
// slice interpolated into a message. It takes issuer names, never URLs: see
// issuerNames.
func logIssuersConfigured(l *slog.Logger, names []string) {
	ctx := context.Background()
	for _, name := range names {
		logging.Emit(ctx, l, logging.EventOIDCIssuerConfigured,
			slog.String("issuer_name", name),
			slog.Int("issuer_count", len(names)))
	}
}

// issuerNames maps configured issuer URLs onto the names the records carry.
// The full issuer URL is never logged, so a URL with no host becomes the
// placeholder rather than the URL itself.
func issuerNames(issuerURLs []string) []string {
	if len(issuerURLs) == 0 {
		return nil
	}
	names := make([]string, len(issuerURLs))
	for i, issuerURL := range issuerURLs {
		names[i] = probe.IssuerName(issuerURL)
	}
	return names
}

// ErrReported marks an error that was already emitted on the log stream. main
// exits non-zero on it without printing it again, so a failure after the
// logger exists never adds an unstructured line beside the JSON records.
var ErrReported = errors.New("error already reported on the log stream")

// NewRunCommand builds the root command. The signal handler is installed inside
// RunE rather than by the caller, because the shutdown logger it reports
// through is derived from the root logger, which cannot exist until the
// command line has been parsed.
func NewRunCommand() *cobra.Command {
	// Build options
	opts := options.New()

	// Build command
	cmd := buildRunCommand(opts, os.Stdout)

	// Add option flags to command
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
			stopCh := signals.Handler(logging.ForComponent(root, logging.ComponentShutdown))

			if err := checkReservedIdentityPrefixes(opts); err != nil {
				return fail(err)
			}

			// Here we determine to either use custom or 'in-cluster' client configuration
			var restConfig *rest.Config
			if opts.Client.ClientFlagsChanged(cmd) {
				// One or more client flags have been set to use client flag built
				// config
				restConfig, err = opts.Client.ToRESTConfig()
				if err != nil {
					return fail(err)
				}

			} else {
				// No client flags have been set so default to in-cluster config
				restConfig, err = rest.InClusterConfig()
				if err != nil {
					return fail(err)
				}
			}

			// Set client throttling settings for Kubernetes clients.
			if opts.Client.KubeClientBurst > 0 {
				restConfig.Burst = opts.Client.KubeClientBurst
			}
			if opts.Client.KubeClientQPS > 0 {
				restConfig.QPS = opts.Client.KubeClientQPS
			}

			// Initialise token reviewer if enabled. The reviewer is wrapped in
			// a token result cache so repeated reviews of the same token
			// (e.g. request storms during an OIDC issuer outage) do not each
			// cost an API server round trip; NewCached returns the bare
			// reviewer when both TTLs are zero.
			var tokenReviewer authenticator.Token
			if opts.App.TokenPassthrough.Enabled {
				reviewer, err := tokenreview.New(restConfig, opts.App.TokenPassthrough.Audiences,
					opts.App.TokenPassthrough.RequestTimeout,
					logging.ForComponent(root, logging.ComponentTokenReview))
				if err != nil {
					return fail(err)
				}
				tokenReviewer = tokenreview.NewCached(reviewer,
					opts.App.TokenPassthrough.CacheSuccessTTL,
					opts.App.TokenPassthrough.CacheFailureTTL)
			}

			// Initialise Secure Serving Config
			secureServingInfo := new(server.SecureServingInfo)
			if err := opts.SecureServing.ApplyTo(&secureServingInfo); err != nil {
				return fail(err)
			}

			proxyConfig := &proxy.Config{
				TokenReview:          opts.App.TokenPassthrough.Enabled,
				DisableImpersonation: opts.App.DisableImpersonation,

				FlushInterval:   opts.App.FlushInterval,
				ExternalAddress: opts.SecureServing.BindAddress.String(),

				ExtraUserHeaders:                opts.App.ExtraHeaderOptions.ExtraUserHeaders,
				ExtraUserHeadersClientIPEnabled: opts.App.ExtraHeaderOptions.EnableClientIPExtraUserHeader,

				TrustedProxies: opts.App.TrustedProxies,

				AllowedReservedGroups: opts.App.AllowedReservedGroups,
			}

			// Setup Subject Access Review
			kubeclient, err := kubernetes.NewForConfig(restConfig)
			if err != nil {
				return fail(err)
			}

			subjectAccessReviewer, err := subjectaccessreview.New(
				kubeclient.AuthorizationV1().SubjectAccessReviews(),
				opts.App.SubjectAccessReviewTimeout,
				opts.App.SubjectAccessReviewAllowCacheTTL,
				opts.App.SubjectAccessReviewDenyCacheTTL,
				opts.App.MaxImpersonationHeaderValues,
				logging.ForComponent(root, logging.ComponentSAR),
			)
			if err != nil {
				return fail(err)
			}

			oidcLogger := logging.ForComponent(root, logging.ComponentOIDC)

			tokenAuther, issuerURLs, err := buildTokenAuther(opts, oidcLogger, startupLogger)
			if err != nil {
				return fail(err)
			}

			// Initialise proxy with token authenticator
			p, err := proxy.New(proxy.Dependencies{
				Logger:                root,
				RestConfig:            restConfig,
				TokenAuthenticator:    tokenAuther,
				AuditOptions:          opts.Audit,
				TokenReviewer:         tokenReviewer,
				SubjectAccessReviewer: subjectAccessReviewer,
				SecureServingInfo:     secureServingInfo,
				Config:                proxyConfig,
			})
			if err != nil {
				return fail(err)
			}

			logConfigLoaded(startupLogger, configSummary{
				version:       opts.Misc.Version(),
				configHash:    configHash(cmd.Flags()),
				issuerCount:   len(issuerURLs),
				readinessMode: probe.ReadinessMode(opts.App.ReadinessRequireAllIssuers),
			})

			// Build a per-issuer readiness probe entry.
			issuerProbes := make([]probe.IssuerReadiness, 0, len(issuerURLs))
			for _, issuerURL := range issuerURLs {
				fakeJWT, err := token.FakeJWT(issuerURL)
				if err != nil {
					return fail(err)
				}
				issuerProbes = append(issuerProbes, probe.IssuerReadiness{
					IssuerURL: issuerURL,
					FakeJWT:   fakeJWT,
				})
			}

			// Derive a context cancelled when the app stop signal fires, giving the
			// readiness server an explicit shutdown path.
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			go func() {
				select {
				case <-stopCh:
					cancel()
				case <-ctx.Done():
				}
			}()

			// Start readiness probe with an explicit lifecycle. Start binds
			// synchronously so a port-in-use failure surfaces here at startup.
			probeServer := probe.NewServer(strconv.Itoa(opts.App.ReadinessProbePort),
				issuerProbes, opts.App.ReadinessRequireAllIssuers,
				p.OIDCTokenAuthenticator(),
				root)
			if err := probeServer.Start(ctx); err != nil {
				return fail(err)
			}

			// Run proxy
			waitCh, listenerStoppedCh, err := p.Run(stopCh)
			if err != nil {
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
			// unanswered, and a failure in Run would leave it that way.
			probeServer.SetServing()

			<-waitCh
			<-listenerStoppedCh

			logging.Emit(context.Background(), serverLogger, logging.EventProxyServerStopped,
				slog.Int64("duration_ms", time.Since(servingSince).Milliseconds()))

			// Stop the readiness server and wait for its listener to be released.
			shutdownSince := time.Now()
			cancel()
			if err := probeServer.Wait(); err != nil {
				// The readiness server reported readiness.server.failed itself.
				return fmt.Errorf("%w: %w", ErrReported, err)
			}

			hooksErr := p.RunPreShutdownHooks()

			// Reported whether or not a hook failed: the milestone is that the
			// teardown finished, and the failing hook has already named itself.
			logging.Emit(context.Background(), logging.ForComponent(root, logging.ComponentShutdown),
				logging.EventProxyShutdownCompleted,
				slog.Int64("duration_ms", time.Since(shutdownSince).Milliseconds()))

			if hooksErr != nil {
				// Each failing hook reported proxy.hook.failed itself.
				return fmt.Errorf("%w: %w", ErrReported, hooksErr)
			}
			return nil
		},
	}
}

// caFromFile implements oidc.CAContentProvider backed by a PEM file. The
// bundle is re-read on every call, so a file that becomes unreadable after
// startup silently yields an empty bundle; the record below is the only signal
// an operator gets.
type caFromFile struct {
	path string

	// logger is the startup-component logger the unreadable-CA record goes to.
	// Never nil: caContentProvider substitutes a discarding logger.
	logger *slog.Logger
}

func (c caFromFile) CurrentCABundleContent() []byte {
	data, err := os.ReadFile(c.path)
	if err != nil {
		logging.Emit(context.Background(), c.logger, logging.EventProxyConfigInvalid,
			slog.String("reason", "ca_file_unreadable"),
			logging.ErrAttr(err))
	}
	return data
}

// caContentProvider returns the CAContentProvider to use for a given path.
// When path is empty it returns nil, signalling oidc.New() to use the system certificate pool.
func caContentProvider(path string, logger *slog.Logger) oidc.CAContentProvider {
	if path == "" {
		return nil
	}
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	return caFromFile{path: path, logger: logger}
}

// buildTokenAuther builds the token authenticator and returns the issuer URLs
// backing it. oidcLogger carries the per-issuer configuration records and
// startupLogger the configuration failures a CA file can raise later.
func buildTokenAuther(opts *options.Options, oidcLogger, startupLogger *slog.Logger) (authenticator.Token, []string, error) {
	if opts.AuthenticationConfig.ConfigFile != "" {
		return buildUnionAuther(opts, oidcLogger)
	}
	return buildSingleAuther(opts.OIDCAuthentication, oidcLogger, startupLogger)
}

// jwtAuthenticatorFromOIDCOptions builds the internal JWTAuthenticator config
// for the single-issuer (--oidc-*) path. Any --oidc-required-claim key=value
// pairs are mapped into ClaimValidationRules so the OIDC authenticator enforces
// them; without this mapping the flag is silently ignored.
func jwtAuthenticatorFromOIDCOptions(o *options.OIDCAuthenticationOptions) apiserverapi.JWTAuthenticator {
	usernamePrefix := o.UsernamePrefix
	groupsPrefix := o.GroupsPrefix

	rules := make([]apiserverapi.ClaimValidationRule, 0, len(o.RequiredClaims))
	for claim, value := range o.RequiredClaims {
		rules = append(rules, apiserverapi.ClaimValidationRule{
			Claim:         claim,
			RequiredValue: value,
		})
	}
	// Map iteration order is randomized; sort for deterministic construction.
	sort.Slice(rules, func(i, j int) bool { return rules[i].Claim < rules[j].Claim })

	return apiserverapi.JWTAuthenticator{
		Issuer: apiserverapi.Issuer{
			URL:       o.IssuerURL,
			Audiences: []string{o.ClientID},
		},
		ClaimMappings: apiserverapi.ClaimMappings{
			Username: apiserverapi.PrefixedClaimOrExpression{
				Claim:  o.UsernameClaim,
				Prefix: &usernamePrefix,
			},
			Groups: apiserverapi.PrefixedClaimOrExpression{
				Claim:  o.GroupsClaim,
				Prefix: &groupsPrefix,
			},
		},
		ClaimValidationRules: rules,
	}
}

func buildSingleAuther(o *options.OIDCAuthenticationOptions, oidcLogger, startupLogger *slog.Logger) (authenticator.Token, []string, error) {
	jwtConfig := jwtAuthenticatorFromOIDCOptions(o)
	client, err := oidcHTTPClient(o.CAFile, nil, o.TLSClientCertFile, o.TLSClientKeyFile)
	if err != nil {
		return nil, nil, fmt.Errorf("creating OIDC HTTP client for issuer %q: %w", o.IssuerURL, err)
	}

	provider := caContentProvider(o.CAFile, startupLogger)
	if client != nil {
		provider = nil
	}
	auther, err := oidc.New(context.Background(), oidc.Options{
		CAContentProvider:    provider,
		Client:               client,
		SupportedSigningAlgs: o.SigningAlgs,
		JWTAuthenticator:     jwtConfig,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("creating OIDC authenticator for issuer %q: %w", o.IssuerURL, err)
	}
	logIssuersConfigured(oidcLogger, issuerNames([]string{o.IssuerURL}))

	return proxy.WithIssuerName(probe.IssuerName(o.IssuerURL), auther), []string{o.IssuerURL}, nil
}

func buildUnionAuther(opts *options.Options, oidcLogger *slog.Logger) (authenticator.Token, []string, error) {
	// One CEL compiler shared by document validation and every authenticator:
	// CEL environments are expensive to construct.
	compiler := authenticationcel.NewDefaultCompiler()

	authCfg, err := opts.AuthenticationConfig.Load(compiler)
	if err != nil {
		return nil, nil, err
	}

	authers := make([]authenticator.Token, 0, len(authCfg.JWT))
	issuerURLs := make([]string, 0, len(authCfg.JWT))
	for _, jwtEntry := range authCfg.JWT {
		auther, err := oidcAutherFromJWT(jwtEntry, compiler, oidc.AllValidSigningAlgorithms(), opts.OIDCAuthentication)
		if err != nil {
			return nil, nil, fmt.Errorf("building authenticator for issuer %q: %w", jwtEntry.Issuer.URL, err)
		}
		authers = append(authers, proxy.WithIssuerName(issuerNameFor(jwtEntry), auther))
		issuerURLs = append(issuerURLs, jwtEntry.Issuer.URL)
	}

	logIssuersConfigured(oidcLogger, issuerNames(issuerURLs))

	return tokenunion.NewFailOnError(authers...), issuerURLs, nil
}

// issuerNameFor returns the name a request authenticated by this
// authentication-config entry is attributed to. An operator-supplied name
// would take precedence, but the vendored JWTAuthenticator carries none, so
// the name is the issuer URL's host: the full URL is never logged.
func issuerNameFor(jwtEntry apiserverapi.JWTAuthenticator) string {
	return probe.IssuerName(jwtEntry.Issuer.URL)
}

func oidcAutherFromJWT(
	jwtConfig apiserverapi.JWTAuthenticator,
	compiler authenticationcel.Compiler,
	signingAlgs []string,
	transportOptions *options.OIDCAuthenticationOptions,
) (authenticator.Token, error) {
	var provider oidc.CAContentProvider
	if jwtConfig.Issuer.CertificateAuthority != "" {
		var err error
		provider, err = dynamiccertificates.NewStaticCAContent("oidc-authenticator", []byte(jwtConfig.Issuer.CertificateAuthority))
		if err != nil {
			return nil, fmt.Errorf("invalid certificateAuthority for issuer %q: %w", jwtConfig.Issuer.URL, err)
		}
	}

	client, err := oidcHTTPClient(
		"",
		[]byte(jwtConfig.Issuer.CertificateAuthority),
		transportOptions.TLSClientCertFile,
		transportOptions.TLSClientKeyFile,
	)
	if err != nil {
		return nil, fmt.Errorf("creating OIDC HTTP client for issuer %q: %w", jwtConfig.Issuer.URL, err)
	}
	if client != nil {
		provider = nil
	}

	return oidc.New(context.Background(), oidc.Options{
		CAContentProvider:    provider,
		Client:               client,
		SupportedSigningAlgs: signingAlgs,
		JWTAuthenticator:     jwtConfig,
		Compiler:             compiler,
	})
}

func oidcHTTPClient(caFile string, caData []byte, certFile, keyFile string) (*http.Client, error) {
	if certFile == "" {
		return nil, nil
	}

	roundTripper, err := rest.TransportFor(&rest.Config{
		TLSClientConfig: rest.TLSClientConfig{
			CAFile:   caFile,
			CAData:   caData,
			CertFile: certFile,
			KeyFile:  keyFile,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("building OIDC TLS transport: %w", err)
	}

	return &http.Client{Transport: roundTripper, Timeout: oidcHTTPTimeout}, nil
}
