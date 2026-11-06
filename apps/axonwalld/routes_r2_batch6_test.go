package main

import (
	"errors"
	"testing"
)

// Round-2 batch 6 (daemon mediums) regression tests for A-M13: a
// routing document that parses cleanly but has no `routes` key must
// error (or, for state.json candidates, fall through) instead of being
// accepted as "zero routes" and pruning every owned route.

func TestR2Batch6RoutingDocRoutesNullReturnsError(t *testing.T) {
	for _, doc := range []string{
		"routes:\n",
		"routes: null\n",
		`{"routes": null}`,
	} {
		if _, err := LoadRoutingConfigFromBytes([]byte(doc)); !errors.Is(err, errNoRoutesKey) {
			t.Fatalf("expected errNoRoutesKey for %q, got: %v", doc, err)
		}
	}
}

func TestR2Batch6RoutingDocWrongSchemaReturnsError(t *testing.T) {
	// An interfaces.yaml accidentally written to routing.yaml.
	interfaces := "interfaces:\n  - name: lan\n    device: ens18\n    enabled: true\n"
	if _, err := LoadRoutingConfigFromBytes([]byte(interfaces)); !errors.Is(err, errNoRoutesKey) {
		t.Fatalf("expected errNoRoutesKey for an interfaces-shaped document, got: %v", err)
	}
	// A typo'd top-level key (`route:` instead of `routes:`).
	typo := "route:\n  - network: 10.0.0.0/24\n    gateway: 10.0.0.1\n"
	if _, err := LoadRoutingConfigFromBytes([]byte(typo)); !errors.Is(err, errNoRoutesKey) {
		t.Fatalf("expected errNoRoutesKey for a typo'd top-level key, got: %v", err)
	}
	// `routes` present but not a list.
	notList := "routes: 5\n"
	if _, err := LoadRoutingConfigFromBytes([]byte(notList)); !errors.Is(err, errNoRoutesKey) {
		t.Fatalf("expected errNoRoutesKey for a non-list routes value, got: %v", err)
	}
}

func TestR2Batch6RoutingDocEmptyIsStillZeroRoutes(t *testing.T) {
	for _, doc := range []string{
		"",
		"  \n\n",
		"# only a comment\n",
		"routes: []\n",
		`{"routes": []}`,
	} {
		cfg, err := LoadRoutingConfigFromBytes([]byte(doc))
		if err != nil {
			t.Fatalf("expected no error for %q, got: %v", doc, err)
		}
		if len(cfg.Routes) != 0 {
			t.Fatalf("expected 0 routes for %q, got %d", doc, len(cfg.Routes))
		}
	}
}

func TestR2Batch6RoutingDocStateJsonWithoutRoutesSignalsFallThrough(t *testing.T) {
	// A state.json grab-bag document legitimately has no top-level
	// routes; LoadRoutingConfigFromBytes reports that with the
	// sentinel so LoadRoutingConfig can try the next candidate
	// instead of failing closed or returning an empty desired set.
	stateJson := `{"interfaces": [{"name": "lan", "device": "ens18"}], "version": "1"}`
	if _, err := LoadRoutingConfigFromBytes([]byte(stateJson)); !errors.Is(err, errNoRoutesKey) {
		t.Fatalf("expected errNoRoutesKey for a routes-less state.json document, got: %v", err)
	}
	// A state.json that does carry routes still parses.
	withRoutes := `{"routes": [{"network": "10.0.0.0/24", "gateway": "10.0.0.1"}]}`
	cfg, err := LoadRoutingConfigFromBytes([]byte(withRoutes))
	if err != nil {
		t.Fatalf("expected no error for a state.json with routes, got: %v", err)
	}
	if len(cfg.Routes) != 1 || cfg.Routes[0].Network != "10.0.0.0/24" {
		t.Fatalf("unexpected routes parsed from state.json: %+v", cfg.Routes)
	}
}
