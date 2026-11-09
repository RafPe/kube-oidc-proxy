// Copyright Jetstack Ltd. See LICENSE for details.
package proxy

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"k8s.io/apimachinery/pkg/util/sets"
	authuser "k8s.io/apiserver/pkg/authentication/user"
)

type Config struct {
	// DisableImpersonation forwards authenticated requests without
	// impersonation and without the proxy's own credentials
	// (--disable-impersonation): authentication consumed the OIDC token, so
	// the request reaches the API server as system:anonymous, and any client
	// Impersonate-* headers travel on unchecked by the proxy, for the API
	// server to authorize against that anonymous identity.
	DisableImpersonation bool

	// TokenPassthrough lets a bearer token the OIDC authenticator rejects be
	// reviewed with the API server's TokenReview, and forwarded unimpersonated
	// when the API server accepts it (--token-passthrough).
	TokenPassthrough bool

	// AllowedReservedGroups names "system:"-prefixed groups the operator has
	// explicitly permitted from a token claim. Empty (the default) refuses every
	// reserved group. Reserved usernames are always refused; see
	// checkReservedIdentity for why the guard exists.
	AllowedReservedGroups []string

	FlushInterval time.Duration

	ExtraUserHeaders                map[string][]string
	ExtraUserHeadersClientIPEnabled bool

	// TrustedProxies is the list of CIDRs (IPv4 or IPv6) whose immediate peers
	// are trusted to set X-Forwarded-For. It is validated and parsed at
	// construction. Empty (the default) trusts no proxy, so the direct peer is
	// always used as the client IP and forwarded headers cannot be spoofed.
	TrustedProxies []string
}

// ValidateAllowedReservedGroups reports whether groups is a valid
// AllowedReservedGroups value, by the rule New applies, so the command layer
// can report a bad flag alongside its other flag errors. The error carries no
// package prefix; the caller names the flag.
func ValidateAllowedReservedGroups(groups []string) error {
	_, err := parseAllowedReservedGroups(groups)
	return err
}

// ValidateTrustedProxies reports whether cidrs is a valid TrustedProxies
// value, by the rule New applies, so the command layer can report a bad flag
// alongside its other flag errors. The error carries no package prefix; the
// caller names the flag.
func ValidateTrustedProxies(cidrs []string) error {
	_, err := parseTrustedProxies(cidrs)
	return err
}

// parseAllowedReservedGroups turns the configured allowlist into a set. Every
// entry must itself carry the reserved prefix: allowing a group that was never
// going to be refused is a no-op, and silently accepting it would hide a typo
// in a security-relevant setting. system:authenticated is rejected as an entry
// because the guard always permits it.
func parseAllowedReservedGroups(groups []string) (sets.Set[string], error) {
	if len(groups) == 0 {
		return nil, nil
	}

	allowed := sets.New[string]()
	for _, group := range groups {
		switch {
		case strings.TrimSpace(group) == "":
			return nil, errors.New("allowed reserved group must not be empty")
		case !strings.HasPrefix(group, ReservedIdentityPrefix):
			return nil, fmt.Errorf("allowed reserved group %q does not carry the reserved %q prefix, so listing it has no effect",
				group, ReservedIdentityPrefix)
		case group == authuser.AllAuthenticated:
			return nil, fmt.Errorf("allowed reserved group %q is always permitted, so listing it has no effect", group)
		}
		allowed.Insert(group)
	}

	return allowed, nil
}

// parseTrustedProxies parses a list of CIDR strings (IPv4 or IPv6) into
// networks. Empty or whitespace-only entries are rejected so a malformed flag
// value cannot be silently ignored. A nil/empty input yields a nil slice,
// meaning no proxy is trusted.
func parseTrustedProxies(cidrs []string) ([]*net.IPNet, error) {
	if len(cidrs) == 0 {
		return nil, nil
	}
	nets := make([]*net.IPNet, 0, len(cidrs))
	for _, c := range cidrs {
		c = strings.TrimSpace(c)
		if c == "" {
			return nil, errors.New("empty trusted-proxy CIDR")
		}
		_, network, err := net.ParseCIDR(c)
		if err != nil {
			return nil, fmt.Errorf("invalid trusted-proxy CIDR %q: %w", c, err)
		}
		nets = append(nets, network)
	}
	return nets, nil
}
