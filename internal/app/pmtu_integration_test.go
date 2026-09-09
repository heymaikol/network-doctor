//go:build integration

package app

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"sync"
	"sync/atomic"
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
			defer ln.Close()
			target, err := diagnostic.ParseTarget(ln.Addr().String())
			if err != nil || target.Proto != diagnostic.ProtoNone {
				t.Fatalf("unknown target: %v, %v", target, err)
			}
			var received atomic.Int64
			var connections atomic.Int64
			var readers sync.WaitGroup
			accepted := make(chan struct{})
			go func() {
				defer close(accepted)
				for {
					conn, err := ln.Accept()
					if err != nil {
						return
					}
					connections.Add(1)
					readers.Add(1)
					go func() {
						defer readers.Done()
						defer conn.Close()
						if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
							t.Errorf("receiver deadline: %v", err)
							return
						}
						n, err := io.Copy(io.Discard, conn)
						received.Add(n)
						if err != nil {
							t.Errorf("receiver: %v", err)
						}
					}()
				}
			}()
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
			ln.Close()
			<-accepted
			readers.Wait()
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
			if tc.skip == "" && connections.Load() == 0 {
				t.Error("no ordinary TCP connection reached the receiver")
			}
			t.Logf("receiver: %d application bytes across %d connections", received.Load(), connections.Load())
			if got := received.Load(); got != tc.want {
				t.Errorf("receiver got %d application bytes, want %d; report: %s", got, tc.want, &stdout)
			}
		})
	}
}
