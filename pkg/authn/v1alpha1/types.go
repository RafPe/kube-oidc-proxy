// Copyright Jetstack Ltd. See LICENSE for details.

// Package v1alpha1 holds the kube-oidc-proxy.rafpe.github.io/v1alpha1
// authentication configuration that kube-oidc-proxy reads. ADR-0001
// (docs/decisions/0001-route-same-issuer-entries-by-audience.md) gives the
// reasons for this kind.
package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	apiserverv1 "k8s.io/apiserver/pkg/apis/apiserver/v1"
)

const (
	// GroupName is the API group of the configuration kinds of the proxy.
	GroupName = "kube-oidc-proxy.rafpe.github.io"

	// APIVersion is the apiVersion value of a document of this package.
	APIVersion = GroupName + "/v1alpha1"

	// Kind is the kind value of an authentication configuration document.
	Kind = "AuthenticationConfiguration"
)

// AuthenticationConfiguration is the authentication configuration document of
// the proxy. Each issuer has a name. Two issuers can have the same issuer URL
// when their audiences are disjoint.
type AuthenticationConfiguration struct {
	metav1.TypeMeta `json:",inline"`

	// Issuers are the issuers the proxy accepts tokens from.
	Issuers []Issuer `json:"issuers"`
}

// Issuer is one named issuer.
type Issuer struct {
	// Name is the issuer_name of the issuer in logs and metrics. It is a
	// DNS-1123 subdomain and is unique in the document.
	Name string `json:"name"`

	// JWT is the upstream Kubernetes JWT authenticator configuration of the
	// issuer. Its CEL expressions can use authenticationConfiguration.issuer.name.
	// The proxy replaces that reference with a string literal of Name before
	// the upstream validation.
	JWT apiserverv1.JWTAuthenticator `json:"jwt"`
}
