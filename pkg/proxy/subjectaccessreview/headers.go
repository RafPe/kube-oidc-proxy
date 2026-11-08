// Copyright Jetstack Ltd. See LICENSE for details.
package subjectaccessreview

import (
	"net/http"
	"strings"

	"k8s.io/client-go/transport"
)

// IsImpersonationHeader reports whether key names an impersonation header.
// The match is on the Impersonate- prefix, case-insensitively: a header a
// client spells unusually, or one of a kind this proxy does not know, is still
// an impersonation attempt and must be authorized or refused, never forwarded.
func IsImpersonationHeader(key string) bool {
	return hasPrefixFold(key, "Impersonate-")
}

// isKnownImpersonationHeader reports whether key is one of the impersonation
// header kinds CheckAuthorizedForImpersonation authorizes: user, uid, group or
// an extra.
func isKnownImpersonationHeader(key string) bool {
	return strings.EqualFold(key, transport.ImpersonateUserHeader) ||
		strings.EqualFold(key, transport.ImpersonateUIDHeader) ||
		strings.EqualFold(key, transport.ImpersonateGroupHeader) ||
		hasPrefixFold(key, transport.ImpersonateUserExtraHeaderPrefix)
}

// HasImpersonationHeaders reports whether the headers carry any impersonation
// header at all, which is what decides whether a request goes through
// CheckAuthorizedForImpersonation.
func HasImpersonationHeaders(headers http.Header) bool {
	for key := range headers {
		if IsImpersonationHeader(key) {
			return true
		}
	}
	return false
}

// StripImpersonationHeaders returns a copy of headers without the
// impersonation headers, for the request that is forwarded once they have
// been authorized and turned into the outbound identity.
func StripImpersonationHeaders(headers http.Header) http.Header {
	out := make(http.Header, len(headers))
	for key, values := range headers {
		if IsImpersonationHeader(key) {
			continue
		}
		out[key] = append([]string(nil), values...)
	}
	return out
}

// hasPrefixFold is strings.HasPrefix without regard to case.
func hasPrefixFold(s, prefix string) bool {
	return len(s) >= len(prefix) && strings.EqualFold(s[:len(prefix)], prefix)
}

// countImpersonationHeaderValues returns the total number of impersonation
// header values the request carries: every value of every header
// IsImpersonationHeader matches, exactly as the consumption loop in
// CheckAuthorizedForImpersonation matches them.
func countImpersonationHeaderValues(headers http.Header) int {
	count := 0
	for key, values := range headers {
		if IsImpersonationHeader(key) {
			count += len(values)
		}
	}
	return count
}
