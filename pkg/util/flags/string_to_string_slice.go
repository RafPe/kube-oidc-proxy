// Copyright Jetstack Ltd. See LICENSE for details.

// Package flags provides custom pflag.Value implementations used by the
// command-line interface.
package flags

import (
	"bytes"
	"encoding/csv"
	"fmt"
	"strings"

	"github.com/spf13/pflag"
)

// This is a struct to implement the pflag.Value interface to introduce a
// map[string][]string flag type.
type stringToStringSliceValue struct {
	values *map[string][]string
}

var _ pflag.Value = &stringToStringSliceValue{}

// NewStringToStringSliceValue returns a pflag.Value interface that implements
// a flag that takes values into the map[string][]slice data structure.
func NewStringToStringSliceValue(p *map[string][]string) pflag.Value {
	return &stringToStringSliceValue{
		values: p,
	}
}

// Set parses a comma-separated list of key=value pairs, e.g. a=-7,b=2,a=3.
// A key may repeat; its values accumulate in order, across repeated flags
// too. A malformed value is rejected without changing what earlier flags set.
func (s *stringToStringSliceValue) Set(val string) error {
	// A value built without the constructor still ends up with a map to read.
	if s.values == nil {
		s.values = new(map[string][]string)
	}
	if *s.values == nil {
		*s.values = make(map[string][]string)
	}
	if val == "" {
		return nil
	}

	pairs, err := csv.NewReader(strings.NewReader(val)).Read()
	if err != nil {
		return err
	}

	parsed := make([][2]string, 0, len(pairs))
	for _, pair := range pairs {
		k, v, ok := strings.Cut(pair, "=")
		if !ok || strings.Contains(v, "=") {
			return fmt.Errorf("%s must be formatted as key=value", pair)
		}
		parsed = append(parsed, [2]string{k, v})
	}

	for _, kv := range parsed {
		(*s.values)[kv[0]] = append((*s.values)[kv[0]], kv[1])
	}
	return nil
}

func (s *stringToStringSliceValue) Type() string {
	return "stringToStringSlice"
}

func (s *stringToStringSliceValue) String() string {
	var records []string
	for k, vs := range *s.values {
		for _, v := range vs {
			records = append(records, k+"="+v)
		}
	}

	var buf bytes.Buffer
	w := csv.NewWriter(&buf)
	if err := w.Write(records); err != nil {
		panic(err)
	}

	w.Flush()
	return "[" + strings.TrimSpace(buf.String()) + "]"
}
