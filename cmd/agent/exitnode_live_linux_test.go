//go:build linux

package main

import (
	"errors"
	"os"
	"testing"

	"github.com/vishvananda/netlink"
)

// TestApplyExitRoutesLive exercises the real netlink calls against a
// dummy interface. It needs CAP_NET_ADMIN, so it self-skips on normal
// dev boxes/CI and runs inside a user+net namespace:
//
//	go test -c -o /tmp/agent.test ./cmd/agent && unshare -rn /tmp/agent.test -test.run TestApplyExitRoutesLive -test.v
func TestApplyExitRoutesLive(t *testing.T) {
	link := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "exitlive0"}}
	if err := netlink.LinkAdd(link); err != nil {
		if errors.Is(err, os.ErrPermission) {
			t.Skipf("needs CAP_NET_ADMIN (run inside unshare -rn): %v", err)
		}
		t.Fatalf("LinkAdd() returned error: %v", err)
	}
	t.Cleanup(func() { _ = netlink.LinkDel(link) })
	if err := netlink.LinkSetUp(link); err != nil {
		t.Fatalf("LinkSetUp() returned error: %v", err)
	}

	tableRoutes := func(family int) []netlink.Route {
		t.Helper()
		routes, err := netlink.RouteListFiltered(family,
			&netlink.Route{Table: exitRouteTable}, netlink.RT_FILTER_TABLE)
		if err != nil {
			t.Fatalf("RouteListFiltered() returned error: %v", err)
		}
		return routes
	}
	exitRules := func(family int) []netlink.Rule {
		t.Helper()
		rules, err := netlink.RuleList(family)
		if err != nil {
			t.Fatalf("RuleList() returned error: %v", err)
		}
		var ours []netlink.Rule
		for _, r := range rules {
			if r.Priority == exitRulePrefSuppress || r.Priority == exitRulePrefFwmark {
				ours = append(ours, r)
			}
		}
		return ours
	}

	enabled := false
	if err := applyExitRoutes("exitlive0", true, true, &enabled); err != nil {
		t.Fatalf("applyExitRoutes(active) returned error: %v", err)
	}
	if !enabled {
		t.Fatal("enabled flag not set")
	}

	// Idempotent re-apply (every sync tick does this).
	if err := applyExitRoutes("exitlive0", true, true, &enabled); err != nil {
		t.Fatalf("re-apply returned error: %v", err)
	}

	for _, family := range []int{netlink.FAMILY_V4, netlink.FAMILY_V6} {
		if got := tableRoutes(family); len(got) != 1 {
			t.Fatalf("family %d: table %d routes = %v, want exactly the default route", family, exitRouteTable, got)
		}
		rules := exitRules(family)
		if len(rules) != 2 {
			t.Fatalf("family %d: exit rules = %+v, want suppress + not-fwmark", family, rules)
		}
		for _, r := range rules {
			switch r.Priority {
			case exitRulePrefSuppress:
				if r.SuppressPrefixlen != 0 {
					t.Fatalf("family %d: suppress rule = %+v", family, r)
				}
			case exitRulePrefFwmark:
				if !r.Invert || r.Mark != exitFwmark || r.Table != exitRouteTable {
					t.Fatalf("family %d: fwmark rule = %+v", family, r)
				}
			}
		}
	}

	if err := applyExitRoutes("exitlive0", false, false, &enabled); err != nil {
		t.Fatalf("applyExitRoutes(inactive) returned error: %v", err)
	}
	if enabled {
		t.Fatal("enabled flag not cleared")
	}
	for _, family := range []int{netlink.FAMILY_V4, netlink.FAMILY_V6} {
		if got := tableRoutes(family); len(got) != 0 {
			t.Fatalf("family %d: routes left after teardown: %v", family, got)
		}
		if got := exitRules(family); len(got) != 0 {
			t.Fatalf("family %d: rules left after teardown: %+v", family, got)
		}
	}
}
