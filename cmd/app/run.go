// Copyright Jetstack Ltd. See LICENSE for details.

// Package app assembles the kube-oidc-proxy command: it wires the OIDC
// authenticator, token/subject-access reviewers, readiness probe and proxy
// together and runs them until the supplied stop channel is closed.
package app

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"
	apiserverapi "k8s.io/apiserver/pkg/apis/apiserver"
	"k8s.io/apiserver/pkg/authentication/authenticator"
	authenticationcel "k8s.io/apiserver/pkg/authentication/cel"
	tokenunion "k8s.io/apiserver/pkg/authentication/token/union"
	"k8s.io/apiserver/pkg/server"
	"k8s.io/apiserver/pkg/server/dynamiccertificates"
	"k8s.io/apiserver/plugin/pkg/authenticator/token/oidc"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/klog/v2"

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

// NewRunCommand builds the root command. The signal handler is installed inside
// RunE rather than by the caller, because the shutdown logger it reports
// through is derived from the root logger, which cannot exist until the
// command line has been parsed.
func NewRunCommand() *cobra.Command {
	// Build options
	opts := options.New()

	// Build command
	cmd := buildRunCommand(opts)

	// Add option flags to command
	opts.AddFlags(cmd)

	return cmd
}

// Proxy command
func buildRunCommand(opts *options.Options) *cobra.Command {
	return &cobra.Command{
		Use:  options.AppName,
		Long: "kube-oidc-proxy is a reverse proxy to authenticate users to Kubernetes API servers with Open ID Connect Authentication.",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := opts.Validate(cmd); err != nil {
				return err
			}

			// One root logger for the whole process, built from the flags and
			// injected into every collaborator below; no package holds its own.
			root, err := logging.New(opts.Logging.ToLoggerOptions(os.Stdout))
			if err != nil {
				return err
			}
			slog.SetDefault(root)

			// Trap SIGINT/SIGTERM only once the root logger exists, so shutdown
			// reports through the configured stream. Nothing is serving before
			// this point, so a signal that arrives earlier ends the process
			// with Go's default behaviour.
			stopCh := signals.Handler(logging.ForComponent(root, logging.ComponentShutdown))

			if err := checkReservedIdentityPrefixes(opts); err != nil {
				return err
			}

			// Here we determine to either use custom or 'in-cluster' client configuration
			var restConfig *rest.Config
			if opts.Client.ClientFlagsChanged(cmd) {
				// One or more client flags have been set to use client flag built
				// config
				restConfig, err = opts.Client.ToRESTConfig()
				if err != nil {
					return err
				}

			} else {
				// No client flags have been set so default to in-cluster config
				restConfig, err = rest.InClusterConfig()
				if err != nil {
					return err
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
					return err
				}
				tokenReviewer = tokenreview.NewCached(reviewer,
					opts.App.TokenPassthrough.CacheSuccessTTL,
					opts.App.TokenPassthrough.CacheFailureTTL)
			}

			// Initialise Secure Serving Config
			secureServingInfo := new(server.SecureServingInfo)
			if err := opts.SecureServing.ApplyTo(&secureServingInfo); err != nil {
				return err
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
				return err
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
				return err
			}

			tokenAuther, issuerURLs, err := buildTokenAuther(opts)
			if err != nil {
				return err
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
				return err
			}

			// Build a per-issuer readiness probe entry.
			issuerProbes := make([]probe.IssuerReadiness, 0, len(issuerURLs))
			for _, issuerURL := range issuerURLs {
				fakeJWT, err := token.FakeJWT(issuerURL)
				if err != nil {
					return err
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
				logging.ForComponent(root, logging.ComponentReadiness))
			if err := probeServer.Start(ctx); err != nil {
				return err
			}

			// Run proxy
			waitCh, listenerStoppedCh, err := p.Run(stopCh)
			if err != nil {
				return err
			}

			// The handler chain is built and the secure server is serving its
			// listener. Only now may the pod be advertised as ready: the port
			// has been bound since SecureServing.ApplyTo above, so before this
			// point a client connect succeeds and then sits in the backlog
			// unanswered, and a failure in Run would leave it that way.
			probeServer.SetServing()

			<-waitCh
			<-listenerStoppedCh

			// Stop the readiness server and wait for its listener to be released.
			cancel()
			if err := probeServer.Wait(); err != nil {
				return err
			}

			if err := p.RunPreShutdownHooks(); err != nil {
				return err
			}

			return nil
		},
	}
}

// caFromFile implements oidc.CAContentProvider backed by a PEM file.
type caFromFile struct {
	path string
}

func (c caFromFile) CurrentCABundleContent() []byte {
	data, err := os.ReadFile(c.path)
	if err != nil {
		klog.Errorf("failed to read CA file %q: %v", c.path, err)
	}
	return data
}

// caContentProvider returns the CAContentProvider to use for a given path.
// When path is empty it returns nil, signalling oidc.New() to use the system certificate pool.
func caContentProvider(path string) oidc.CAContentProvider {
	if path == "" {
		return nil
	}
	return caFromFile{path: path}
}

func buildTokenAuther(opts *options.Options) (authenticator.Token, []string, error) {
	if opts.AuthenticationConfig.ConfigFile != "" {
		return buildUnionAuther(opts)
	}
	return buildSingleAuther(opts.OIDCAuthentication)
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

func buildSingleAuther(o *options.OIDCAuthenticationOptions) (authenticator.Token, []string, error) {
	jwtConfig := jwtAuthenticatorFromOIDCOptions(o)
	client, err := oidcHTTPClient(o.CAFile, nil, o.TLSClientCertFile, o.TLSClientKeyFile)
	if err != nil {
		return nil, nil, fmt.Errorf("creating OIDC HTTP client for issuer %q: %w", o.IssuerURL, err)
	}

	provider := caContentProvider(o.CAFile)
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
	return auther, []string{o.IssuerURL}, nil
}

func buildUnionAuther(opts *options.Options) (authenticator.Token, []string, error) {
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
		authers = append(authers, auther)
		issuerURLs = append(issuerURLs, jwtEntry.Issuer.URL)
	}

	klog.Infof("configured OIDC issuers: %v", issuerURLs)

	return tokenunion.NewFailOnError(authers...), issuerURLs, nil
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
