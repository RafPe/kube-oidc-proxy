// Copyright Jetstack Ltd. See LICENSE for details.

// Package authn assembles the proxy's token authenticator: one OIDC
// authenticator per configured issuer, combined into a union, whether the
// issuers come from an AuthenticationConfiguration or from the single issuer
// the --oidc-* flags describe. It also owns how an issuer is
// named in records and metrics (IssuerName) and how the issuer that accepted a
// token is reported back out of the authenticator (AttributeToIssuer), so the
// whole capability has one home.
package authn
