// Copyright Jetstack Ltd. See LICENSE for details.
package proxy

import (
	"net"
	"strings"
	"testing"
)

// FuzzParseTrustedProxies drives trusted-proxy CIDR parsing with arbitrary
// input. Getting this wrong decides whether X-Forwarded-For is believed, so a
// malformed entry must fail loudly rather than yield a partial or unexpectedly
// wide set of networks.
func FuzzParseTrustedProxies(f *testing.F) {
	for _, seed := range []string{
		"",
		"10.0.0.0/8",
		" 192.168.0.1/32 ",
		"2001:db8::/32",
		"not-a-cidr",
		"10.0.0.0/8,not-a-cidr",
		"10.0.0.0/8, ,192.168.0.0/16",
		"10.0.0.1/0",
		"::/0",
	} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, joined string) {
		cidrs := strings.Split(joined, ",")

		nets, err := parseTrustedProxies(cidrs)
		if err != nil {
			if nets != nil {
				t.Fatalf("networks returned alongside error %q: %v", err, nets)
			}
			return
		}

		if len(nets) != len(cidrs) {
			t.Fatalf("parsed %d networks from %d entries (%q)", len(nets), len(cidrs), joined)
		}

		for i, n := range nets {
			if n == nil {
				t.Fatalf("entry %d (%q) parsed to a nil network", i, cidrs[i])
			}
			// A parsed network is always the masked base address, so it must
			// contain itself and survive a canonical-form round trip.
			if !n.Contains(n.IP) {
				t.Fatalf("network %s does not contain its own base address", n)
			}
			_, again, err := net.ParseCIDR(n.String())
			if err != nil {
				t.Fatalf("re-parsing %s from entry %q: %s", n, cidrs[i], err)
			}
			if again.String() != n.String() {
				t.Fatalf("round trip changed %s into %s", n, again)
			}
		}
	})
}
