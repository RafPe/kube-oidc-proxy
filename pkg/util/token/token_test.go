// Copyright Jetstack Ltd. See LICENSE for details.
package token

import (
	"net/http"
	"testing"
)

func TestParseFromRequest(t *testing.T) {
	tests := map[string]struct {
		req   *http.Request
		token string
		ok    bool
	}{
		"should return !ok if request is nil": {
			req:   nil,
			token: "",
			ok:    false,
		},
		"should return !ok if request.Header is nil": {
			req: &http.Request{
				Header: nil,
			},
			token: "",
			ok:    false,
		},
		"should return !ok if no Authorization header given": {
			req: &http.Request{
				Header: map[string][]string{
					"Random-Header1": {"foo bar"},
					"Random-Header2": {"boo koo"},
				},
			},
			token: "",
			ok:    false,
		},
		"should return !ok if Authorization header is empty": {
			req: &http.Request{
				Header: map[string][]string{
					"Random-Header1": {"foo bar"},
					"Authorization":  {},
				},
			},
			token: "",
			ok:    false,
		},
		"should return !ok if Authorization header is only 'bearer'": {
			req: &http.Request{
				Header: map[string][]string{
					"Random-Header1": {"foo bar"},
					"Authorization":  {"bearer"},
				},
			},
			token: "",
			ok:    false,
		},
		"should return !ok if Authorization header is only 'bearertoken'": {
			req: &http.Request{
				Header: map[string][]string{
					"Random-Header1": {"foo bar"},
					"Authorization":  {"bearertoken"},
				},
			},
			token: "",
			ok:    false,
		},
		"should return 'token' if Authorization header is 'bearer token'": {
			req: &http.Request{
				Header: map[string][]string{
					"Random-Header1": {"foo bar"},
					"Authorization":  {"bearer token"},
				},
			},
			token: "token",
			ok:    true,
		},
		"should return !ok if Authorization header is 'bearer token' but not first element": {
			req: &http.Request{
				Header: map[string][]string{
					"Random-Header1": {"foo bar"},
					"Authorization":  {"foo bar", "bearer token"},
				},
			},
			token: "",
			ok:    false,
		},
		"should return 'token' if Authorization header is 'bearer token some-other-string'": {
			req: &http.Request{
				Header: map[string][]string{
					"Random-Header1": {"foo bar"},
					"Authorization":  {"bearer token some-other-string"},
				},
			},
			token: "token",
			ok:    true,
		},
		"should return 'token' if Authorization header is 'bearer token' but mixed capitals on bearer": {
			req: &http.Request{
				Header: map[string][]string{
					"Random-Header1": {"foo bar"},
					"Authorization":  {"BeAREr token"},
				},
			},
			token: "token",
			ok:    true,
		},
		"should return !ok if Authorization header is 'bearer token' but the header name is title capitalised": {
			req: &http.Request{
				Header: map[string][]string{
					"Random-Header1": {"foo bar"},
					"authorization":  {"bearer token"},
				},
			},
			token: "",
			ok:    false,
		},
		"should return !ok if Authorization header has multiple spaces between 'bearer' and 'token'": {
			req: &http.Request{
				Header: map[string][]string{
					"Random-Header1": {"foo bar"},
					"Authorization":  {"bearer     token"},
				},
			},
			token: "",
			ok:    false,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			gToken, gok := ParseFromRequest(test.req)

			if test.ok != gok {
				t.Errorf("unexpected ok, exp=%t got=%t",
					test.ok, gok)
			}

			if test.token != gToken {
				t.Errorf("unexpected token, exp=%s got=%s",
					test.token, gToken)
			}
		})
	}
}
