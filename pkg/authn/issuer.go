// Copyright Jetstack Ltd. See LICENSE for details.
package authn

import (
	"context"
	"log/slog"
	"net/url"
	"strings"

	"github.com/rafpe/kube-oidc-proxy/pkg/logging"
)

// unknownIssuerName is what a record or metric reports for an issuer whose
// URL yields no usable host.
const unknownIssuerName = "unknown"

// IssuerName is how an issuer is named on every record and every metric
// series: the host of its URL, bounded like any identity. The full URL is
// never used, so a value with no host — an opaque URI, the empty string —
// becomes unknownIssuerName. The raw input is never returned.
func IssuerName(issuerURL string) string {
	u, err := url.Parse(issuerURL)
	if err != nil || u.Host == "" {
		return unknownIssuerName
	}
	if host := strings.TrimSpace(logging.Bound(u.Host, logging.MaxIdentity)); host != "" {
		return host
	}
	return unknownIssuerName
}

// issuerNames maps configured issuer URLs onto the names the records carry.
// The proxy's own records name an issuer by this, never by its full URL, so a
// URL with no host becomes the placeholder rather than the URL itself.
func issuerNames(issuerURLs []string) []string {
	if len(issuerURLs) == 0 {
		return nil
	}
	names := make([]string, len(issuerURLs))
	for i, issuerURL := range issuerURLs {
		names[i] = IssuerName(issuerURL)
	}
	return names
}

// duplicateIssuerName reports the first issuer name two configured issuer URLs
// map onto, together with the positions of the entry already stored under
// that name and of the one that collided with it. Names are hosts (see
// IssuerName), so issuers that differ only by path collide -- and then the
// name alone does not say which two configuration entries have to change.
func duplicateIssuerName(issuerURLs []string) (name string, first, other int, dup bool) {
	seen := make(map[string]int, len(issuerURLs))
	for i, n := range issuerNames(issuerURLs) {
		if firstIndex, ok := seen[n]; ok {
			return n, firstIndex, i, true
		}
		seen[n] = i
	}
	return "", 0, 0, false
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
