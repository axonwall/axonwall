package main

import (
	"encoding/json"
	"testing"
)

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

// B2-M7: the SYNC_ROUTES payload carries the routes the controller
// pushed earlier that are no longer enabled, so the satellite can
// delete them from the kernel.
func TestSyncRoutesPayloadCarriesDeletions(t *testing.T) {
	var p SyncRoutesPayload
	if err := json.Unmarshal([]byte(`{"routes":[{"destination":"10.1.0.0/24","gateway":"10.0.0.254","device":"eth0"}],"routesToDelete":[{"destination":"10.2.0.0/24","gateway":"10.0.0.254","device":"eth0"}]}`), &p); err != nil {
		t.Fatalf("unmarshalling a SYNC_ROUTES payload must succeed: %v", err)
	}
	if len(p.Routes) != 1 || p.Routes[0].Destination != "10.1.0.0/24" {
		t.Fatalf("routes parsed as %+v, want one route to 10.1.0.0/24", p.Routes)
	}
	if len(p.RoutesToDelete) != 1 || p.RoutesToDelete[0].Destination != "10.2.0.0/24" {
		t.Fatalf("routesToDelete parsed as %+v, want one route to 10.2.0.0/24", p.RoutesToDelete)
	}
	// The delete list is optional: older hubs send only routes.
	var p2 SyncRoutesPayload
	if err := json.Unmarshal([]byte(`{"routes":[]}`), &p2); err != nil {
		t.Fatalf("unmarshalling a routes-only payload must succeed: %v", err)
	}
	if len(p2.RoutesToDelete) != 0 {
		t.Fatalf("routesToDelete must default to empty, got %+v", p2.RoutesToDelete)
	}
}
