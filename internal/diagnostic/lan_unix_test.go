//go:build linux || darwin

package diagnostic

import (
	"context"
	"errors"
	"net"
	"syscall"
	"testing"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

func TestLANValidatesICMPEchoReply(t *testing.T) {
	nonce := []byte("fresh probe nonce")
	for _, tc := range []struct {
		name string
		typ  ipv4.ICMPType
		code int
		seq  int
		data []byte
		want bool
	}{
		{"reply", ipv4.ICMPTypeEchoReply, 0, 1, nonce, true},
		{"request", ipv4.ICMPTypeEcho, 0, 1, nonce, false},
		{"wrong code", ipv4.ICMPTypeEchoReply, 1, 1, nonce, false},
		{"wrong sequence", ipv4.ICMPTypeEchoReply, 0, 2, nonce, false},
		{"wrong payload", ipv4.ICMPTypeEchoReply, 0, 1, []byte("old probe nonce"), false},
	} {
		msg := icmp.Message{Type: tc.typ, Code: tc.code, Body: &icmp.Echo{ID: 12, Seq: tc.seq, Data: tc.data}}
		wire, err := msg.Marshal(nil)
		if err != nil {
			t.Fatal(err)
		}
		if got := lanEchoReply(wire, nonce); got != tc.want {
			t.Errorf("%s: match = %t, want %t", tc.name, got, tc.want)
		}
	}
	if lanEchoReply([]byte{0, 0, 0}, nonce) {
		t.Error("truncated reply matched")
	}
}

func TestLANICMPSendErrorClassification(t *testing.T) {
	for _, tc := range []struct {
		name   string
		err    error
		denied bool
	}{
		{"local EPERM", syscall.EPERM, true},
		{"wrapped EPERM", &net.OpError{Op: "write", Err: syscall.EPERM}, true},
		{"host unreachable", syscall.EHOSTUNREACH, false},
		{"destination blocked", syscall.EACCES, false},
		{"canceled", context.Canceled, false},
		{"deadline", context.DeadlineExceeded, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := lanICMPSendError(tc.err)
			if errors.Is(err, errLANICMPSendDenied) != tc.denied || (err != nil) != tc.denied {
				t.Fatalf("classified %v as %v, want denial %t", tc.err, err, tc.denied)
			}
		})
	}
}
