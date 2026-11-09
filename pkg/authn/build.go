// Copyright Jetstack Ltd. See LICENSE for details.
package authn

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"sort"
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

// oidcHTTPTimeout bounds every call an authenticator makes to its issuer.
const oidcHTTPTimeout = 30 * time.Second

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
// file can raise later. Every per-issuer authenticator is wrapped by
// AttributeToIssuer, so a request names the issuer that accepted its token.
func Build(cfg Config, oidcLogger, startupLogger *slog.Logger) (authenticator.Token, []string, error) {
	if cfg.ConfigFile != "" {
		return buildUnion(cfg, oidcLogger)
	}
	return buildSingle(cfg, oidcLogger, startupLogger)
}

// jwtAuthenticatorFromIssuer builds the internal JWTAuthenticator config for
// the single-issuer path. Any required claim key=value pairs are mapped into
// ClaimValidationRules so the OIDC authenticator enforces them; without this
// mapping the flag would be silently ignored.
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
	sort.Slice(rules, func(a, b int) bool { return rules[a].Claim < rules[b].Claim })

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

func buildSingle(cfg Config, oidcLogger, startupLogger *slog.Logger) (authenticator.Token, []string, error) {
	issuer := cfg.Issuer
	jwtConfig := jwtAuthenticatorFromIssuer(issuer)
	client, err := oidcHTTPClient(issuer.CAFile, nil, cfg.TLSClientCertFile, cfg.TLSClientKeyFile)
	if err != nil {
		return nil, nil, fmt.Errorf("creating OIDC HTTP client for issuer %q: %w", issuer.URL, err)
	}

	// A client certificate means a dedicated HTTP client that already carries
	// the CA; the authenticator takes the CA directly only when it builds the
	// client itself.
	var provider oidc.CAContentProvider
	if client == nil {
		provider = caContentProvider(issuer.CAFile, startupLogger)
	}
	authn, err := oidc.New(context.Background(), oidc.Options{
		CAContentProvider:    provider,
		Client:               client,
		SupportedSigningAlgs: issuer.SigningAlgs,
		JWTAuthenticator:     jwtConfig,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("creating OIDC authenticator for issuer %q: %w", issuer.URL, err)
	}
	logIssuersConfigured(oidcLogger, issuerNames([]string{issuer.URL}))

	return AttributeToIssuer(IssuerName(issuer.URL), authn), []string{issuer.URL}, nil
}

func buildUnion(cfg Config, oidcLogger *slog.Logger) (authenticator.Token, []string, error) {
	// One CEL compiler shared by document validation and every authenticator:
	// CEL environments are expensive to construct.
	compiler := authenticationcel.NewDefaultCompiler()

	authCfg, err := LoadConfiguration(cfg.ConfigFile, compiler)
	if err != nil {
		return nil, nil, err
	}

	// Issuers are named by host in every record and every metric series. Two
	// issuers on one host with different paths would share a name, and a
	// per-issuer gauge cannot tell them apart, so the configuration is refused
	// here, before any authenticator is built or any issuer is reported.
	issuerURLs := make([]string, 0, len(authCfg.JWT))
	for _, jwtEntry := range authCfg.JWT {
		issuerURLs = append(issuerURLs, jwtEntry.Issuer.URL)
	}
	if name, first, other, dup := duplicateIssuerName(issuerURLs); dup {
		return nil, nil, fmt.Errorf("two configured issuers share the name %q (%q and %q); issuers must differ by host", name, first, other)
	}

	authenticators := make([]authenticator.Token, 0, len(authCfg.JWT))
	for _, jwtEntry := range authCfg.JWT {
		authn, err := oidcAuthenticatorFromJWT(jwtEntry, compiler, oidc.AllValidSigningAlgorithms(), cfg)
		if err != nil {
			return nil, nil, fmt.Errorf("building authenticator for issuer %q: %w", jwtEntry.Issuer.URL, err)
		}
		authenticators = append(authenticators, AttributeToIssuer(IssuerName(jwtEntry.Issuer.URL), authn))
	}

	logIssuersConfigured(oidcLogger, issuerNames(issuerURLs))

	return tokenunion.NewFailOnError(authenticators...), issuerURLs, nil
}

func oidcAuthenticatorFromJWT(
	jwtConfig apiserverapi.JWTAuthenticator,
	compiler authenticationcel.Compiler,
	signingAlgs []string,
	cfg Config,
) (authenticator.Token, error) {
	client, err := oidcHTTPClient(
		"",
		[]byte(jwtConfig.Issuer.CertificateAuthority),
		cfg.TLSClientCertFile,
		cfg.TLSClientKeyFile,
	)
	if err != nil {
		return nil, fmt.Errorf("creating OIDC HTTP client for issuer %q: %w", jwtConfig.Issuer.URL, err)
	}

	// As in buildSingle: a dedicated client already carries the CA, so the
	// authenticator takes it directly only when there is no client.
	var provider oidc.CAContentProvider
	if client == nil && jwtConfig.Issuer.CertificateAuthority != "" {
		provider, err = dynamiccertificates.NewStaticCAContent("oidc-authenticator", []byte(jwtConfig.Issuer.CertificateAuthority))
		if err != nil {
			return nil, fmt.Errorf("invalid certificateAuthority for issuer %q: %w", jwtConfig.Issuer.URL, err)
		}
	}

	return oidc.New(context.Background(), oidc.Options{
		CAContentProvider:    provider,
		Client:               client,
		SupportedSigningAlgs: signingAlgs,
		JWTAuthenticator:     jwtConfig,
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
			slog.String("reason", "ca_file_unreadable"),
			logging.ErrAttr(err))
	}
	return data
}

// caContentProvider returns the CAContentProvider to use for a given path.
// When path is empty it returns nil, signalling oidc.New() to use the system
// certificate pool.
func caContentProvider(path string, logger *slog.Logger) oidc.CAContentProvider {
	if path == "" {
		return nil
	}
	return caFromFile{path: path, logger: logger}
}
