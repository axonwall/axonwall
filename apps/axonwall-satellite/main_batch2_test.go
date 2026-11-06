package main

import "testing"

// B-H4 residual regression: the hub must not trust its latched
// headscaleEnrolled flag alone, because a wiped/reimaged
// satellite reconnects with the same ID and is never
// re-provisioned. The satellite reports its live tailscale login
// state in every telemetry report, parsed from `tailscale status
// --json` BackendState. Only a definite verdict is reported:
// Running means enrolled, the logged-out states mean not
// enrolled, and anything indeterminate (Starting, unparsable
// output) is nil so the hub ignores the field.

func TestParseTailscaleBackendState(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want *bool
	}{
		{name: "Running is enrolled", in: `{"BackendState":"Running"}`, want: boolPtr(true)},
		{name: "NeedsLogin is not enrolled", in: `{"BackendState":"NeedsLogin"}`, want: boolPtr(false)},
		{name: "NoState is not enrolled", in: `{"BackendState":"NoState"}`, want: boolPtr(false)},
		{name: "Stopped is not enrolled", in: `{"BackendState":"Stopped"}`, want: boolPtr(false)},
		{name: "NeedsMachineAuth is not enrolled", in: `{"BackendState":"NeedsMachineAuth"}`, want: boolPtr(false)},
		{name: "Starting is indeterminate", in: `{"BackendState":"Starting"}`, want: nil},
		{name: "unknown state is indeterminate", in: `{"BackendState":"SomethingElse"}`, want: nil},
		{name: "missing BackendState is indeterminate", in: `{}`, want: nil},
		{name: "unparsable output is indeterminate", in: `not json`, want: nil},
		{name: "empty output is indeterminate", in: ``, want: nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := parseTailscaleBackendState([]byte(tc.in))
			if tc.want == nil {
				if got != nil {
					t.Fatalf("parseTailscaleBackendState(%q) = %v, want nil", tc.in, *got)
				}
				return
			}
			if got == nil {
				t.Fatalf("parseTailscaleBackendState(%q) = nil, want %v", tc.in, *tc.want)
			}
			if *got != *tc.want {
				t.Fatalf("parseTailscaleBackendState(%q) = %v, want %v", tc.in, *got, *tc.want)
			}
		})
	}
}

func boolPtr(b bool) *bool { return &b }
