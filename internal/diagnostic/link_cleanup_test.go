package diagnostic

import (
	"context"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// A target link must not hold a socket once RunAll returns, whatever the
// selection, the faults, or the cancellation. These checks look at the sockets
// themselves: every connection the run opened to the target has to be closed.

// trackSockets records each connection a run opens to the target port: the
// Target TCP connect and every fresh TLS dial. afterConnect runs once, after
// the first connect succeeds, so a test can cancel the run at that point.
func trackSockets(f *budgetFixture, o *netops, afterConnect func()) *connLog {
	sockets := &connLog{}
	var first sync.Once
	dial := o.dialContext
	o.dialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		c, err := dial(ctx, network, addr)
		if err != nil || !strings.HasSuffix(addr, ":443") {
			return c, err
		}
		first.Do(afterConnect)
		return sockets.add(c), nil
	}
	o.dialTLS = trustingDialTLS(o.dialContext, f.roots)
	return sockets
}

// requireSocketsClosed waits for every tracked socket to end. The wait is only
// a bound: a socket the owner closes always ends within it, and a socket that
// nothing closes never does.
func requireSocketsClosed(t *testing.T, sockets *connLog) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		open := 0
		for _, c := range sockets.all() {
			if !c.closed.Load() {
				open++
			}
		}
		if open == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%d of %d target sockets still open after RunAll returned", open, len(sockets.all()))
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// Every selection that can hand a socket along, under each fault that ends the
// run early, leaves no socket open when RunAll returns.
func TestRunAllLeavesNoTargetSocketOpen(t *testing.T) {
	selections := []struct {
		name  string
		check map[ProbeID]struct{}
	}{
		{"tcp", map[ProbeID]struct{}{ProbeTargetTCP: {}}},
		{"tcp and tls", map[ProbeID]struct{}{ProbeTargetTCP: {}, ProbeTLS: {}}},
		{"tcp and https", map[ProbeID]struct{}{ProbeTargetTCP: {}, ProbeHTTPS: {}}},
		{"tls and https", map[ProbeID]struct{}{ProbeTLS: {}, ProbeHTTPS: {}}},
		{"all rows", healthyHTTPSRows},
	}
	for _, sel := range selections {
		for _, fault := range []string{"healthy", "cancelled after connect", "cancelled before run"} {
			t.Run(sel.name+"/"+fault, func(t *testing.T) {
				f := newBudgetFixture(t)
				o := f.ops()
				ctx, cancel := context.WithCancel(context.Background())
				t.Cleanup(cancel)
				afterConnect := func() {}
				switch fault {
				case "cancelled after connect":
					afterConnect = cancel
				case "cancelled before run":
					cancel()
				}
				sockets := trackSockets(f, o, afterConnect)
				probes := ProbeSelection{Check: sel.check}.Apply(o.timedProbes(mustTarget(t, budgetTargetHost+":443"), DefaultPublicDNS, true))
				RunAll(ctx, probes, DefaultProbeTimeout)
				requireSocketsClosed(t, sockets)
				if fault == "healthy" && len(sockets.all()) == 0 {
					t.Fatal("a healthy run opened no target socket, so the check proves nothing")
				}
			})
		}
	}
}

// Target TCP offers its socket, and the consumer that would take it is skipped
// because another prerequisite failed. No row takes the socket, so RunAll has to
// close it itself.
func TestRunAllClosesASocketNoRowTook(t *testing.T) {
	link := newTargetLink()
	link.toTLS = true
	client, server := net.Pipe()
	t.Cleanup(func() { _ = server.Close() })
	tc := &trackedConn{Conn: client}
	probes := []Probe{
		{ID: "gate", Run: func(context.Context, map[ProbeID]ProbeResult) ProbeResult {
			return ProbeResult{Status: StatusFail}
		}},
		{ID: ProbeTargetTCP, Run: func(context.Context, map[ProbeID]ProbeResult) ProbeResult {
			if !link.offer(tc) {
				t.Error("an empty link refused the socket")
			}
			return ProbeResult{Status: StatusPass}
		}, link: link},
		{ID: ProbeTLS, Deps: []ProbeID{ProbeTargetTCP, "gate"}, Run: func(context.Context, map[ProbeID]ProbeResult) ProbeResult {
			t.Error("TLS ran although a prerequisite failed")
			return ProbeResult{Status: StatusPass}
		}, link: link},
	}
	res := RunAll(context.Background(), probes, DefaultProbeTimeout)
	if got := res[ProbeTLS].Status; got != StatusSkip {
		t.Fatalf("TLS = %v, want skip: a prerequisite failed", got)
	}
	if !tc.closed.Load() {
		t.Error("RunAll returned with an offered socket that no row took, and nothing closed it")
	}
}
