// Copyright Jetstack Ltd. See LICENSE for details.
package options

import (
	"reflect"
	"testing"

	"github.com/spf13/pflag"
)

func TestStringToStringSliceSet(t *testing.T) {
	tests := map[string]struct {
		val       string
		expError  bool
		expValues map[string][]string
	}{
		"if empty string set, no values": {
			val:       "",
			expError:  false,
			expValues: make(map[string][]string),
		},
		"if only key then error": {
			val:       "key1",
			expError:  true,
			expValues: make(map[string][]string),
		},
		"if single key value return": {
			val:      "key1=foo",
			expError: false,
			expValues: map[string][]string{
				"key1": {"foo"},
			},
		},
		"if two keys with two values return": {
			val:      "key1=foo,key2=bar",
			expError: false,
			expValues: map[string][]string{
				"key1": {"foo"},
				"key2": {"bar"},
			},
		},
		"if 3 keys with 5 values return": {
			val:      "key1=foo,key2=bar,key1=a,key2=c,key3=c",
			expError: false,
			expValues: map[string][]string{
				"key1": {"foo", "a"},
				"key2": {"bar", "c"},
				"key3": {"c"},
			},
		},
		"if key with no value error": {
			val:       "key1=foo,key2=bar,key1=a,key2=c,key3",
			expError:  true,
			expValues: make(map[string][]string),
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			var got map[string][]string
			s := newStringToStringSliceValue(&got)

			err := s.Set(test.val)
			if test.expError != (err != nil) {
				t.Fatalf("got unexpected error: %v", err)
			}

			if !reflect.DeepEqual(test.expValues, got) {
				t.Errorf("unexpected values, exp=%v got=%v", test.expValues, got)
			}
		})
	}
}

// TestStringToStringSliceReachesTheBoundField pins that what the flag parses
// lands in the field it was registered against, accumulated across repeated
// flags, rather than in a map only the flag value can see.
func TestStringToStringSliceReachesTheBoundField(t *testing.T) {
	var headers map[string][]string
	fs := pflag.NewFlagSet("test", pflag.ContinueOnError)
	fs.Var(newStringToStringSliceValue(&headers), "extra-user-headers", "")

	if err := fs.Parse([]string{
		"--extra-user-headers=team=a,region=eu",
		"--extra-user-headers=team=b",
	}); err != nil {
		t.Fatal(err)
	}

	want := map[string][]string{"team": {"a", "b"}, "region": {"eu"}}
	if !reflect.DeepEqual(headers, want) {
		t.Fatalf("bound field = %v, want %v", headers, want)
	}
}

// TestStringToStringSliceStringIsDeterministic pins String() to sorted key
// order: config_hash folds every flag's String() into its digest, so map
// iteration order leaking into it fingerprints identical pods differently.
// Each key's values keep their insertion order, which is the order the
// impersonation headers are sent in.
func TestStringToStringSliceStringIsDeterministic(t *testing.T) {
	values := map[string][]string{}
	v := newStringToStringSliceValue(&values)
	if err := v.Set("team=b,region=eu,tier=gold,zone=z,owner=ops,team=a"); err != nil {
		t.Fatal(err)
	}

	const want = "[owner=ops,region=eu,team=b,team=a,tier=gold,zone=z]"
	for range 50 {
		if got := v.String(); got != want {
			t.Fatalf("String() = %q, want %q", got, want)
		}
	}
}
