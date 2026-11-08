// Copyright Jetstack Ltd. See LICENSE for details.
package proxy

import (
	"fmt"
	"net"
	"strings"
	"time"

	"k8s.io/apimachinery/pkg/util/sets"
)

type Config struct {
	DisableImpersonation bool
	TokenReview          bool

	// AllowedReservedGroups names "system:"-prefixed groups the operator has
	// explicitly permitted from a token claim. Empty (the default) refuses every
	// reserved group. Reserved usernames are always refused; see
	// checkReservedIdentity for why the guard exists.
	AllowedReservedGroups []string

	FlushInterval   time.Duration
	ExternalAddress string

	ExtraUserHeaders                map[string][]string
	ExtraUserHeadersClientIPEnabled bool

	// TrustedProxies is the list of CIDRs (IPv4 or IPv6) whose immediate peers
	// are trusted to set X-Forwarded-For. It is validated and parsed at
	// construction. Empty (the default) trusts no proxy, so the direct peer is
	// always used as the client IP and forwarded headers cannot be spoofed.
	TrustedProxies []string
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
			return nil, fmt.Errorf("allowed reserved group must not be empty")
		case !strings.HasPrefix(group, ReservedIdentityPrefix):
			return nil, fmt.Errorf("allowed reserved group %q does not carry the reserved %q prefix, so listing it has no effect",
				group, ReservedIdentityPrefix)
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
			return nil, fmt.Errorf("proxy: empty trusted-proxy CIDR")
		}
		_, network, err := net.ParseCIDR(c)
		if err != nil {
			return nil, fmt.Errorf("proxy: invalid trusted-proxy CIDR %q: %w", c, err)
		}
		nets = append(nets, network)
	}
	return nets, nil
}

// cloneHeaderMap returns a deep copy of a header map so the Proxy never shares
// mutable state with its caller. A nil input yields nil.
func cloneHeaderMap(in map[string][]string) map[string][]string {
	if in == nil {
		return nil
	}
	out := make(map[string][]string, len(in))
	for k, vs := range in {
		out[k] = append([]string(nil), vs...)
	}
	return out
}
