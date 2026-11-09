// Copyright Jetstack Ltd. See LICENSE for details.
package authn

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"slices"
	"time"

	apiserverapi "k8s.io/apiserver/pkg/apis/apiserver"
	"k8s.io/apiserver/pkg/authentication/authenticator"
	authenticationcel "k8s.io/apiserver/pkg/authentication/cel"
	tokenunion "k8s.io/apiserver/pkg/authentication/token/union"
	"k8s.io/apiserver/pkg/server/dynamiccertificates"
	"k8s.io/apiserver/plugin/pkg/authenticator/token/oidc"
	"k8s.io/client-go/rest"

	"github.com/rafpe/kube-oidc-proxy/pkg/logging"
)

// oidcHTTPTimeout bounds every call the dedicated client-certificate HTTP
// client makes to an issuer. It is the same 30s that oidc.New gives the
// client it builds itself when no client certificate is configured, so an
// issuer call is bounded at 30s either way; it is set here only because a
// client handed to oidc.New is used as is.
const oidcHTTPTimeout = 30 * time.Second

// configInvalidReason is the closed vocabulary of the reason a
// proxy.config.invalid record carries. It is deliberately disjoint from the
// request-path metrics.Reason set: these are startup configuration failures,
// not refusals of a request.
type configInvalidReason string

// reasonCAFileUnreadable reports an --oidc-ca-file that could not be read when
// the authenticator asked for the issuer's CA bundle.
const reasonCAFileUnreadable configInvalidReason = "ca_file_unreadable"

// IssuerConfig is the single issuer the --oidc-* flags describe.
type IssuerConfig struct {
	URL      string
	ClientID string

	// CAFile verifies the issuer's serving certificate; empty means the
	// system roots.
	CAFile string

	UsernameClaim  string
	UsernamePrefix string
	GroupsClaim    string
	GroupsPrefix   string

	SigningAlgs    []string
	RequiredClaims map[string]string
}

// Config describes the issuers the proxy authenticates against.
type Config struct {
	// ConfigFile is the AuthenticationConfiguration document for multi-issuer
	// mode. When set it is authoritative and Issuer is ignored.
	ConfigFile string

	// Issuer is the single issuer configured through flags, used when no
	// ConfigFile is set.
	Issuer IssuerConfig

	// TLSClientCertFile and TLSClientKeyFile are the client certificate
	// presented to every issuer, in both modes. Empty means none.
	TLSClientCertFile string
	TLSClientKeyFile  string
}

// Build constructs the token authenticator for cfg and returns the issuer
// URLs backing it, in configuration order. oidcLogger carries the per-issuer
// configuration records and startupLogger the configuration failures a CA
// file can raise later; both are required. Every per-issuer authenticator is
// wrapped by AttributeToIssuer, so a request names the issuer that accepted
// its token.
func Build(cfg Config, oidcLogger, startupLogger *slog.Logger) (authenticator.Token, []string, error) {
	if oidcLogger == nil {
		return nil, nil, errors.New("authn: oidc logger is required")
	}
	if startupLogger == nil {
		return nil, nil, errors.New("authn: startup logger is required")
	}

	// One CEL compiler shared by document validation and every authenticator:
	// CEL environments are expensive to construct.
	compiler := authenticationcel.NewDefaultCompiler()

	issuers, err := configuredIssuers(cfg, compiler)
	if err != nil {
		return nil, nil, fmt.Errorf("authn: %w", err)
	}
	token, issuerURLs, err := buildIssuers(issuers, compiler, cfg, oidcLogger, startupLogger)
	if err != nil {
		return nil, nil, fmt.Errorf("authn: %w", err)
	}
	return token, issuerURLs, nil
}

// issuer is one issuer to authenticate against, whichever way it was
// configured.
type issuer struct {
	jwt apiserverapi.JWTAuthenticator

	// caFile is the --oidc-ca-file path, re-read on every use. An issuer from
	// the configuration document carries its CA inline in
	// jwt.Issuer.CertificateAuthority instead. Neither means the system roots.
	caFile string

	signingAlgs []string
}

// configuredIssuers returns the issuers cfg describes, in configuration order.
//
// The --oidc-* flags describe a one-entry configuration and take the same
// build path as the document. They skip LoadConfiguration only because there
// is no document to decode: the per-entry validation it runs is repeated by
// oidc.New on every entry (CompileAndValidateJWTAuthenticator), and its
// cross-entry checks have nothing to compare one issuer with. Two inputs stay
// flag-specific, because the flags define them differently: the CA is a file
// re-read on every use rather than inline content, and the signing algorithms
// are --oidc-signing-algs rather than every valid one.
func configuredIssuers(cfg Config, compiler authenticationcel.Compiler) ([]issuer, error) {
	if cfg.ConfigFile == "" {
		return []issuer{{
			jwt:         jwtAuthenticatorFromIssuer(cfg.Issuer),
			caFile:      cfg.Issuer.CAFile,
			signingAlgs: cfg.Issuer.SigningAlgs,
		}}, nil
	}

	authCfg, err := LoadConfiguration(cfg.ConfigFile, compiler)
	if err != nil {
		return nil, err
	}
	issuers := make([]issuer, 0, len(authCfg.JWT))
	for _, jwtEntry := range authCfg.JWT {
		issuers = append(issuers, issuer{jwt: jwtEntry, signingAlgs: oidc.AllValidSigningAlgorithms()})
	}
	return issuers, nil
}

// jwtAuthenticatorFromIssuer builds the internal JWTAuthenticator config for
// the flag-configured issuer. Any required claim key=value pairs are mapped
// into ClaimValidationRules so the OIDC authenticator enforces them; without
// this mapping the flag would be silently ignored.
func jwtAuthenticatorFromIssuer(i IssuerConfig) apiserverapi.JWTAuthenticator {
	usernamePrefix := i.UsernamePrefix
	groupsPrefix := i.GroupsPrefix

	rules := make([]apiserverapi.ClaimValidationRule, 0, len(i.RequiredClaims))
	for claim, value := range i.RequiredClaims {
		rules = append(rules, apiserverapi.ClaimValidationRule{
			Claim:         claim,
			RequiredValue: value,
		})
	}
	// Map iteration order is randomized; sort for deterministic construction.
	slices.SortFunc(rules, func(a, b apiserverapi.ClaimValidationRule) int { return cmp.Compare(a.Claim, b.Claim) })

	return apiserverapi.JWTAuthenticator{
		Issuer: apiserverapi.Issuer{
			URL:       i.URL,
			Audiences: []string{i.ClientID},
		},
		ClaimMappings: apiserverapi.ClaimMappings{
			Username: apiserverapi.PrefixedClaimOrExpression{
				Claim:  i.UsernameClaim,
				Prefix: &usernamePrefix,
			},
			Groups: apiserverapi.PrefixedClaimOrExpression{
				Claim:  i.GroupsClaim,
				Prefix: &groupsPrefix,
			},
		},
		ClaimValidationRules: rules,
	}
}

// buildIssuers builds one authenticator per issuer and combines them into a
// union that fails on the first error. A union of one behaves exactly as its
// single member: an error or an acceptance is returned as is, and a refusal
// aggregates no errors into a nil one.
func buildIssuers(issuers []issuer, compiler authenticationcel.Compiler, cfg Config, oidcLogger, startupLogger *slog.Logger) (authenticator.Token, []string, error) {
	// Issuers are named by host in every record and every metric series. Two
	// issuers on one host with different paths would share a name, and a
	// per-issuer gauge cannot tell them apart, so the configuration is refused
	// here, before any authenticator is built or any issuer is reported.
	issuerURLs := make([]string, 0, len(issuers))
	for _, iss := range issuers {
		issuerURLs = append(issuerURLs, iss.jwt.Issuer.URL)
	}
	if name, first, other, dup := duplicateIssuerName(issuerURLs); dup {
		return nil, nil, fmt.Errorf("two configured issuers share the name %q (%q and %q); issuers must differ by host", name, first, other)
	}

	authenticators := make([]authenticator.Token, 0, len(issuers))
	for _, iss := range issuers {
		authn, err := newIssuerAuthenticator(iss, compiler, cfg, startupLogger)
		if err != nil {
			return nil, nil, fmt.Errorf("building authenticator for issuer %q: %w", iss.jwt.Issuer.URL, err)
		}
		authenticators = append(authenticators, AttributeToIssuer(IssuerName(iss.jwt.Issuer.URL), authn))
	}

	logIssuersConfigured(oidcLogger, issuerNames(issuerURLs))

	return tokenunion.NewFailOnError(authenticators...), issuerURLs, nil
}

// newIssuerAuthenticator builds the OIDC authenticator for one issuer.
func newIssuerAuthenticator(iss issuer, compiler authenticationcel.Compiler, cfg Config, startupLogger *slog.Logger) (authenticator.Token, error) {
	client, err := oidcHTTPClient(iss.caFile, []byte(iss.jwt.Issuer.CertificateAuthority), cfg.TLSClientCertFile, cfg.TLSClientKeyFile)
	if err != nil {
		return nil, fmt.Errorf("creating OIDC HTTP client: %w", err)
	}

	// A client certificate means a dedicated HTTP client that already carries
	// the CA; the authenticator takes the CA directly only when it builds the
	// client itself.
	var provider oidc.CAContentProvider
	if client == nil {
		provider, err = caContentProvider(iss, startupLogger)
		if err != nil {
			return nil, err
		}
	}

	return oidc.New(context.Background(), oidc.Options{
		CAContentProvider:    provider,
		Client:               client,
		SupportedSigningAlgs: iss.signingAlgs,
		JWTAuthenticator:     iss.jwt,
		Compiler:             compiler,
	})
}

// oidcHTTPClient returns the HTTP client the authenticator calls the issuer
// with when a client certificate is configured, or nil to let the
// authenticator build its own. client-go's transport reloads the certificate
// files, so a rotated client certificate is picked up without a restart.
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

// caFromFile implements oidc.CAContentProvider backed by a PEM file. The
// bundle is re-read on every call, so a file that becomes unreadable after
// startup silently yields an empty bundle; the record below is the only signal
// an operator gets.
type caFromFile struct {
	path string

	// logger is the startup-component logger the unreadable-CA record goes to.
	logger *slog.Logger
}

func (c caFromFile) CurrentCABundleContent() []byte {
	data, err := os.ReadFile(c.path)
	if err != nil {
		logging.Emit(context.Background(), c.logger, logging.EventProxyConfigInvalid,
			slog.String("reason", string(reasonCAFileUnreadable)),
			logging.ErrAttr(err))
	}
	return data
}

// caContentProvider returns the CAContentProvider for an issuer the
// authenticator builds its own client for: the --oidc-ca-file re-read on every
// use, or the document's inline certificateAuthority. With neither it returns
// nil, signalling oidc.New() to use the system certificate pool.
func caContentProvider(iss issuer, logger *slog.Logger) (oidc.CAContentProvider, error) {
	switch {
	case iss.caFile != "":
		return caFromFile{path: iss.caFile, logger: logger}, nil
	case iss.jwt.Issuer.CertificateAuthority != "":
		provider, err := dynamiccertificates.NewStaticCAContent("oidc-authenticator", []byte(iss.jwt.Issuer.CertificateAuthority))
		if err != nil {
			return nil, fmt.Errorf("invalid certificateAuthority: %w", err)
		}
		return provider, nil
	default:
		return nil, nil
	}
}
