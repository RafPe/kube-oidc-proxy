// Copyright Jetstack Ltd. See LICENSE for details.
package options

import (
	"crypto/tls"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/pflag"
	cliflag "k8s.io/component-base/cli/flag"

	"github.com/rafpe/kube-oidc-proxy/pkg/proxy"
)

// OIDCAuthenticationOptions configure the single issuer of the --oidc-* flags,
// and the client certificate presented to issuers in either mode.
type OIDCAuthenticationOptions struct {
	CAFile            string
	TLSClientCertFile string
	TLSClientKeyFile  string
	ClientID          string
	IssuerURL         string
	UsernameClaim     string
	UsernamePrefix    string
	GroupsClaim       string
	GroupsPrefix      string
	SigningAlgs       []string
	RequiredClaims    map[string]string
}

// NewOIDCAuthenticationOptions registers the OIDC flag set on nfs and returns
// the options it binds.
func NewOIDCAuthenticationOptions(nfs *cliflag.NamedFlagSets) *OIDCAuthenticationOptions {
	return new(OIDCAuthenticationOptions).AddFlags(nfs.FlagSet("OIDC"))
}

// Validate checks the options that apply in both single- and multi-issuer
// modes: the TLS client certificate and key presented to issuers.
func (o *OIDCAuthenticationOptions) Validate() error {
	if (o.TLSClientCertFile == "") != (o.TLSClientKeyFile == "") {
		return errors.New("--oidc-tls-client-cert-file and --oidc-tls-client-key-file must be specified together")
	}
	if o.TLSClientCertFile != "" {
		if _, err := tls.LoadX509KeyPair(o.TLSClientCertFile, o.TLSClientKeyFile); err != nil {
			return fmt.Errorf("--oidc-tls-client-cert-file and --oidc-tls-client-key-file: %w", err)
		}
	}
	return nil
}

// ValidateIssuerFlags checks the single-issuer flags and returns every problem
// found, joined. They are mutually exclusive with --authentication-config, so
// the caller runs this only when no configuration file is set; with one, the
// issuer, CA and prefixes come from the document.
//
// The prefix check is an early report, not the guard: the proxy's runtime
// check catches everything this misses, including reserved values that arrive
// in the claim rather than the prefix.
func (o *OIDCAuthenticationOptions) ValidateIssuerFlags() error {
	var errs []error
	if (len(o.IssuerURL) > 0) != (len(o.ClientID) > 0) {
		errs = append(errs, errors.New("--oidc-issuer-url and --oidc-client-id must be specified together"))
	}
	// Validate --oidc-ca-file readability up front: an empty path is allowed
	// (the system root CA set is used), but a configured file that cannot be
	// read is a hard error rather than being silently swallowed at request time.
	if len(o.CAFile) > 0 {
		if _, err := os.ReadFile(o.CAFile); err != nil {
			errs = append(errs, fmt.Errorf("--oidc-ca-file %q: %w", o.CAFile, err))
		}
	}
	// A username or group prefix that is itself reserved would mint reserved
	// identities for every authenticated user.
	for _, prefix := range []struct {
		flag  string
		value string
	}{
		{flag: "--oidc-username-prefix", value: o.UsernamePrefix},
		{flag: "--oidc-groups-prefix", value: o.GroupsPrefix},
	} {
		if strings.HasPrefix(prefix.value, proxy.ReservedIdentityPrefix) {
			errs = append(errs, fmt.Errorf("%s %q would prefix every authenticated identity with the Kubernetes-reserved %q",
				prefix.flag, prefix.value, proxy.ReservedIdentityPrefix))
		}
	}
	return errors.Join(errs...)
}

// AddFlags binds the --oidc-* flags to fs and returns o for chaining.
func (o *OIDCAuthenticationOptions) AddFlags(fs *pflag.FlagSet) *OIDCAuthenticationOptions {
	fs.StringVar(&o.IssuerURL, "oidc-issuer-url", o.IssuerURL,
		"The URL of the OpenID issuer, only HTTPS scheme will be accepted.")

	fs.StringVar(&o.ClientID, "oidc-client-id", o.ClientID,
		"The client ID for the OpenID Connect client.")

	fs.StringVar(&o.CAFile, "oidc-ca-file", o.CAFile,
		"The OpenID server's certificate will be verified by one of the authorities "+
			"in the oidc-ca-file, otherwise the host's root CA set will be used")

	fs.StringVar(&o.TLSClientCertFile, "oidc-tls-client-cert-file", o.TLSClientCertFile,
		"Path to an X.509 client certificate presented to OIDC issuers. "+
			"Requires --oidc-tls-client-key-file and applies to every configured issuer.")

	fs.StringVar(&o.TLSClientKeyFile, "oidc-tls-client-key-file", o.TLSClientKeyFile,
		"Path to the private key for --oidc-tls-client-cert-file.")

	fs.StringVar(&o.UsernameClaim, "oidc-username-claim", "sub",
		"The OpenID claim to use as the username. Note that claims other than the default ('sub') "+
			"is not guaranteed to be unique and immutable")

	// The value is prepended verbatim. kube-apiserver's flag of the same name
	// defaults to prefixing with the issuer URL and treats '-' as "none"; this
	// proxy never has, and adopting that now would rename every user, and
	// so break every RBAC binding, on existing deployments.
	fs.StringVar(&o.UsernamePrefix, "oidc-username-prefix", "",
		"Prefix prepended verbatim to every username, to keep them from clashing with "+
			"other authentication strategies. Empty (the default) means no prefix. Unlike "+
			"kube-apiserver's flag, the issuer URL is never used as a default and '-' is not "+
			"special: it would be prepended like any other value.")

	fs.StringVar(&o.GroupsClaim, "oidc-groups-claim", "",
		"If provided, the name of a custom OpenID Connect claim for specifying user groups. "+
			"The claim value is expected to be a string or array of strings.")

	fs.StringVar(&o.GroupsPrefix, "oidc-groups-prefix", "",
		"Prefix prepended verbatim to every group name, to keep them from clashing with "+
			"other authentication strategies. Empty (the default) means no prefix.")

	fs.StringSliceVar(&o.SigningAlgs, "oidc-signing-algs", []string{"RS256"},
		"Comma-separated list of allowed JOSE asymmetric signing algorithms. JWTs with a "+
			"'alg' header value not in this list will be rejected. "+
			"Values are defined by RFC 7518 https://tools.ietf.org/html/rfc7518#section-3.1.")

	fs.Var(cliflag.NewMapStringStringNoSplit(&o.RequiredClaims), "oidc-required-claim",
		"A key=value pair that describes a required claim in the ID Token. "+
			"If set, the claim is verified to be present in the ID Token with a matching value. "+
			"Repeat this flag to specify multiple claims.")

	return o
}
