package simulation

import (
	"context"
	"testing"

	d "github.com/heymaikol/network-doctor/v2/internal/diagnostic"
	"github.com/heymaikol/network-doctor/v2/internal/snapshot"
)

func labQUICRow(t *testing.T, s LabScenario) snapshot.Check {
	t.Helper()
	r, err := RunLab(context.Background(), s)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range r.Views[0].Snapshot.Checks {
		if c.ID == string(d.ProbeQUIC) {
			return c
		}
	}
	t.Fatal("no QUIC row")
	return snapshot.Check{}
}

// The modeled QUIC row records what it tried, in the shape the live dialer
// records it: the address that answered, an address with no route as its own
// failure, and a silent address as an attempt the probe deadline ended.
func TestLabQUICRowRecordsItsAttempts(t *testing.T) {
	healthy, err := FindLabScenario("healthy-dual-stack")
	if err != nil {
		t.Fatal(err)
	}
	row := labQUICRow(t, healthy)
	if row.Status != snapshot.StatusPass || row.Observed == nil || len(row.Observed.Attempts) == 0 {
		t.Fatalf("healthy QUIC row = %+v, want a pass that records the address that answered", row)
	}
	if last := row.Observed.Attempts[len(row.Observed.Attempts)-1]; last.IP != row.Observed.SelectedIP || last.Cause != "" {
		t.Errorf("winning attempt = %+v, selected %s", last, row.Observed.SelectedIP)
	}

	silent := healthy
	silent.Faults = []LabFault{{ID: "quic-drop", Layer: "transport", Scope: "internet", Network: &Fault{Type: FaultDrop, Node: "internet", Protocol: "udp", Port: 443, Direction: DirectionInbound}}}
	row = labQUICRow(t, silent)
	if row.Status != snapshot.StatusFail || row.Observed == nil || len(row.Observed.Attempts) == 0 {
		t.Fatalf("QUIC row with UDP/443 dropped = %+v, want a failure that records its attempts", row)
	}
	for _, a := range row.Observed.Attempts {
		if a.Cause != d.ConnectionCauseTimeout || !a.Aborted {
			t.Errorf("silent attempt = %+v, want a timeout the probe deadline ended", a)
		}
	}
}
