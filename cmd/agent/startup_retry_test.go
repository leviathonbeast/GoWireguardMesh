package main

import (
	"errors"
	"fmt"
	"net/http"
	"testing"
)

func TestIsPermanentStartupErr(t *testing.T) {
	cases := []struct {
		name      string
		err       error
		permanent bool
	}{
		{"missing setup key", errSetupKeyRequired, true},
		{"wrapped missing setup key", fmt.Errorf("startup: %w", errSetupKeyRequired), true},
		{"bad setup key 401", &enrollRejectedError{status: http.StatusUnauthorized, msg: "enroll rejected"}, true},
		{"revoked key 403", &enrollRejectedError{status: http.StatusForbidden, msg: "enroll rejected"}, true},
		{"rate limited 429", &enrollRejectedError{status: http.StatusTooManyRequests, msg: "enroll rejected"}, false},
		{"proxy with no route 404", &enrollRejectedError{status: http.StatusNotFound, msg: "enroll rejected"}, false},
		{"request timeout 408", &enrollRejectedError{status: http.StatusRequestTimeout, msg: "enroll rejected"}, false},
		{"server error 500", &enrollRejectedError{status: http.StatusInternalServerError, msg: "enroll rejected"}, false},
		{"bad gateway 502", &enrollRejectedError{status: http.StatusBadGateway, msg: "enroll rejected"}, false},
		{"network error", errors.New(`post enroll to "https://mesh": dial tcp: connection refused`), false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isPermanentStartupErr(tc.err); got != tc.permanent {
				t.Fatalf("isPermanentStartupErr(%v) = %v, want %v", tc.err, got, tc.permanent)
			}
		})
	}
}

func TestValidateAdvertiseEndpoint(t *testing.T) {
	valid := []string{"", "213.32.16.141:51820", "mesh.example.uk:51820", "[2001:db8::1]:51820"}
	for _, ep := range valid {
		if err := validateAdvertiseEndpoint(ep); err != nil {
			t.Errorf("validateAdvertiseEndpoint(%q) = %v, want nil", ep, err)
		}
	}

	invalid := []string{"213.32.16.141", ":51820", "host:", "host:0", "host:99999", "host:port"}
	for _, ep := range invalid {
		if err := validateAdvertiseEndpoint(ep); err == nil {
			t.Errorf("validateAdvertiseEndpoint(%q) = nil, want error", ep)
		}
	}
}
