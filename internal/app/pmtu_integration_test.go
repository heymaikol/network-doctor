//go:build integration

package app

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/heymaikol/network-doctor/internal/diagnostic"
	"github.com/heymaikol/network-doctor/internal/report"
	"github.com/heymaikol/network-doctor/internal/ui"
)

func TestUnknownProtocolPMTUPayload(t *testing.T) {
	for _, tc := range []struct {
		name        string
		check, skip string
		watch       bool
		want        int64
	}{
		{name: "default"},
		{name: "explicit", check: "path_mtu", want: 24576},
		{name: "default watch", watch: true},
		{name: "explicit watch", watch: true, check: "path_mtu", want: 2 * 24576},
		{name: "explicit skipped", check: "path_mtu", skip: "path_mtu"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ln, err := net.Listen("tcp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			// Fallback for early failures; rx.stop closes it on the normal
			// path, so the error here is expected and irrelevant.
			defer func() { _ = ln.Close() }()
			target, err := diagnostic.ParseTarget(ln.Addr().String())
			if err != nil || target.Proto != diagnostic.ProtoNone {
				t.Fatalf("unknown target: %v, %v", target, err)
			}
			rx := startReceiver(ln, nil)
			args := []string{"--json", "--no-history", "--no-reference-egress", "--timeout", "1s"}
			if tc.check != "" {
				args = append(args, "--check", tc.check)
			}
			if tc.skip != "" {
				args = append(args, "--skip", tc.skip)
			}
			args = append(args, target.Raw)
			var stdout, stderr bytes.Buffer
			var code int
			passes := 1
			if tc.watch {
				passes = 2
				origEvery := ui.WatchEvery
				t.Cleanup(func() { ui.WatchEvery = origEvery })
				ui.WatchEvery = time.Millisecond
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				var checks probeList
				if tc.check != "" {
					if err := checks.Set(tc.check); err != nil {
						t.Fatal(err)
					}
				}
				h := headless{target: target, watch: true, json: true, timeout: time.Second,
					selection: diagnostic.ProbeSelection{Check: checks.set(), NoReferenceEgress: true}}
				code = runHeadless(ctx, h, &cancelAfter{buf: &stdout, n: passes, cancel: cancel}, &stderr)
			} else {
				code = run(args, &stdout, &stderr)
			}
			// Network Doctor is done, but a connection the kernel accepted and
			// acknowledged may still be waiting in the accept queue. Every
			// non-skipped run makes the ordinary Target TCP connection first.
			minDone := 1
			if tc.skip != "" {
				minDone = 0
			}
			if !rx.await(tc.want, minDone, receiveWait) {
				t.Errorf("receiver read %d application bytes across %d finished connections within %v, want %d; stderr: %s",
					rx.bytes, rx.done, receiveWait, tc.want, &stderr)
			}
			conns := rx.stop(t)
			for _, err := range rx.errs {
				t.Errorf("receiver: %v", err)
			}
			if code != 0 {
				t.Fatalf("exit %d: %s\n%s", code, &stderr, &stdout)
			}
			dec := json.NewDecoder(bytes.NewReader(stdout.Bytes()))
			for range passes {
				var rep report.Report
				if err := dec.Decode(&rep); err != nil {
					t.Fatal(err)
				}
				hasPMTU := false
				for _, check := range rep.Checks {
					if check.ID == string(diagnostic.ProbePMTU) {
						hasPMTU = true
					}
				}
				if hasPMTU != (tc.want > 0) {
					t.Errorf("PMTU report row present = %t, want %t", hasPMTU, tc.want > 0)
				}
			}
			if tc.skip == "" && conns == 0 {
				t.Error("no ordinary TCP connection reached the receiver")
			}
			t.Logf("receiver: %d application bytes across %d connections", rx.bytes, conns)
			if got := rx.bytes; got != tc.want {
				t.Errorf("receiver got %d application bytes, want %d; report: %s", got, tc.want, &stdout)
			}
		})
	}
}

// TestPMTUPayloadAcknowledgedBeforeAccept pins the window behind issue #210.
// The kernel completes and acknowledges a connection before the application
// accepts it, so the probe can truthfully report the payload acknowledged
// while the receiver has read none of it. Closing the listener at that point
// discards the queued connection, so the receiver has to be drained first.
func TestPMTUPayloadAcknowledgedBeforeAccept(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("no TCP send-queue accounting, so acknowledgement is not observable")
	}
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	// Fallback for early failures; rx.stop closes it on the normal path, so
	// the error here is expected and irrelevant.
	defer func() { _ = ln.Close() }()
	hold := make(chan struct{})
	released := false
	release := func() {
		if !released {
			released = true
			close(hold)
		}
	}
	defer release()
	rx := startReceiver(ln, hold)
	var stdout, stderr bytes.Buffer
	code := run([]string{"--json", "--no-history", "--no-reference-egress", "--timeout", "1s",
		"--check", "path_mtu", ln.Addr().String()}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit %d: %s\n%s", code, &stderr, &stdout)
	}
	var rep report.Report
	if err := json.Unmarshal(stdout.Bytes(), &rep); err != nil {
		t.Fatal(err)
	}
	var pmtu *report.Check
	for i := range rep.Checks {
		if rep.Checks[i].ID == string(diagnostic.ProbePMTU) {
			pmtu = &rep.Checks[i]
		}
	}
	if pmtu == nil || pmtu.Status != diagnostic.StatusPass.String() || !strings.Contains(pmtu.Detail, "acknowledged by the peer") {
		t.Fatalf("PMTU row = %+v, want an acknowledged Pass; report: %s", pmtu, &stdout)
	}
	// Only the Target TCP connection has been accepted. Its reader finishing
	// with no bytes is the state the flaky run tore down from.
	if !rx.await(0, 1, receiveWait) || rx.bytes != 0 {
		t.Fatalf("before release: %d bytes across %d finished connections, want 0 across 1", rx.bytes, rx.done)
	}
	release()
	if !rx.await(24576, 2, receiveWait) {
		t.Errorf("after release: %d bytes across %d finished connections, want 24576 across 2", rx.bytes, rx.done)
	}
	if conns := rx.stop(t); conns != 2 || rx.bytes != 24576 || len(rx.errs) != 0 {
		t.Errorf("receiver: %d bytes across %d connections, errors %v; want 24576 across 2", rx.bytes, conns, rx.errs)
	}
}

// receiveWait bounds every receiver wait. Network Doctor has already closed
// its sockets by the time the test waits, so a healthy drain takes
// milliseconds and only a genuine delivery failure runs this out.
const receiveWait = 5 * time.Second

// receiver discards what loopback clients send it and reports back to the
// owning test goroutine, which alone reads its tallies.
type receiver struct {
	ln       net.Listener
	results  chan readResult
	accepted chan int
	bytes    int64
	done     int
	errs     []error
}

type readResult struct {
	n   int64
	err error
}

// startReceiver accepts and drains connections on ln. A non-nil hold keeps
// the second Accept from running until it is closed.
func startReceiver(ln net.Listener, hold <-chan struct{}) *receiver {
	rx := &receiver{ln: ln, results: make(chan readResult), accepted: make(chan int, 1)}
	go func() {
		conns := 0
		for {
			if conns == 1 && hold != nil {
				<-hold
			}
			conn, err := ln.Accept()
			if err != nil {
				rx.accepted <- conns
				return
			}
			conns++
			go func() {
				defer conn.Close()
				var res readResult
				if res.err = conn.SetReadDeadline(time.Now().Add(receiveWait)); res.err == nil {
					res.n, res.err = io.Copy(io.Discard, conn)
				}
				rx.results <- res
			}()
		}
	}()
	return rx
}

func (rx *receiver) add(res readResult) {
	rx.bytes += res.n
	rx.done++
	if res.err != nil {
		rx.errs = append(rx.errs, res.err)
	}
}

// await collects finished readers while the listener stays open, until at
// least want bytes and minDone connections are in, or d runs out.
func (rx *receiver) await(want int64, minDone int, d time.Duration) bool {
	timer := time.NewTimer(d)
	defer timer.Stop()
	for rx.bytes < want || rx.done < minDone {
		select {
		case res := <-rx.results:
			rx.add(res)
		case <-timer.C:
			return false
		}
	}
	return true
}

// stop closes the listener and waits for every accepted reader, returning how
// many connections were accepted. Closing discards anything still in the
// accept queue, so it belongs after await. A failed close would leave the
// accept loop running and the wait below blocked, so it fails the test first.
func (rx *receiver) stop(t *testing.T) int {
	t.Helper()
	if err := rx.ln.Close(); err != nil {
		t.Fatalf("close listener: %v", err)
	}
	conns := <-rx.accepted
	for rx.done < conns {
		rx.add(<-rx.results)
	}
	return conns
}
