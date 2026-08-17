// Copyright Jetstack Ltd. See LICENSE for details.
package flags

import (
	"encoding/csv"
	"strings"
	"testing"
)

// FuzzStringToStringSliceSet drives the map[string][]string flag parser with
// arbitrary values. Set feeds a CSV reader and splits on "=", so it must reject
// malformed input cleanly — leaving no half-populated map behind — and String
// must stay panic-free on whatever it accepted.
func FuzzStringToStringSliceSet(f *testing.F) {
	for _, seed := range []string{
		"",
		"a=1",
		"a=-7,b=2,a=3",
		"a",
		"a=1=2",
		"a=",
		"=1",
		`"a,b"=1`,
		"a=1,\n",
		`"unterminated`,
	} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, val string) {
		m := map[string][]string{}
		v := NewStringToStringSliceValue(&m)

		if err := v.Set(val); err != nil {
			if len(m) != 0 {
				t.Fatalf("map left populated after error %q: %v", err, m)
			}
			return
		}

		// String panics on a CSV write failure; make sure nothing Set accepted
		// can reach that.
		_ = v.String()

		var stored int
		for k, vs := range m {
			if strings.Contains(k, "=") {
				t.Fatalf("key %q contains a separator", k)
			}
			for _, s := range vs {
				if strings.Contains(s, "=") {
					t.Fatalf("value %q for key %q contains a separator", s, k)
				}
			}
			stored += len(vs)
		}

		// Every accepted CSV field must have produced exactly one entry;
		// silently dropping one would widen or narrow the resulting config.
		if want := countFields(val); stored != want {
			t.Fatalf("stored %d entries for %d fields in %q", stored, want, val)
		}
	})
}

// countFields reports how many comma-separated fields Set would have read from
// val, mirroring its CSV reader as an independent oracle.
func countFields(val string) int {
	if len(val) == 0 {
		return 0
	}
	fields, err := csv.NewReader(strings.NewReader(val)).Read()
	if err != nil {
		return 0
	}
	return len(fields)
}
