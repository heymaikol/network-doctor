package sshverify

import (
	"context"
	"encoding/binary"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

// rawDisconnect returns the error the library reports when the server's first packet is a
// plaintext SSH_MSG_DISCONNECT carrying msg. Before key exchange the packets are not encrypted,
// so a bare server can send a disconnect with text of its choosing, and the library puts that
// text into its handshake error.
func rawDisconnect(t *testing.T, msg string) error {
	t.Helper()
	host, _ := newEd25519(t)
	client, server := bufferedPipe()
	payload := []byte{1} // SSH_MSG_DISCONNECT
	payload = binary.BigEndian.AppendUint32(payload, 2)
	payload = appendSSHString(payload, msg)
	payload = appendSSHString(payload, "")
	pad := 4
	for (5+len(payload)+pad)%8 != 0 {
		pad++
	}
	packet := binary.BigEndian.AppendUint32(nil, uint32(1+len(payload)+pad)) // #nosec G115 -- a test packet of a few hundred bytes
	packet = append(packet, byte(pad))
	packet = append(packet, payload...)
	packet = append(packet, make([]byte, pad)...)
	go func() {
		_, _ = server.Write([]byte("SSH-2.0-rawserver\r\n"))
		_, _ = server.Write(packet)
	}()
	conf := &ssh.ClientConfig{
		User:            "user",
		HostKeyCallback: ssh.FixedHostKey(host.PublicKey()), // the handshake ends before any key is checked
	}
	c, _, _, err := ssh.NewClientConn(client, "raw", conf)
	if c != nil {
		_ = c.Close()
	}
	if err == nil {
		t.Fatal("the raw server's disconnect did not end the handshake")
	}
	return err
}

func appendSSHString(b []byte, s string) []byte {
	b = binary.BigEndian.AppendUint32(b, uint32(len(s))) // #nosec G115 -- a test string of a few bytes
	return append(b, s...)
}

// A server can send the refusal text inside its own disconnect, after the password attempt.
// The library then reports that disconnect, and the callback was called once, before the
// attempt's reply. That is not a refusal: the server sent no authentication reply, so the
// outcome is a transport failure and not a refused credential.
func TestServerDisconnectCarryingTheRefusalTextIsNotARefusal(t *testing.T) {
	const text = libraryRefusal + ", attempted methods [password], no supported methods remain"
	err := rawDisconnect(t, text)
	if !strings.Contains(err.Error(), text) {
		t.Fatalf("setup: the library did not carry the server's text into its error: %v", err)
	}
	// The state a disconnect after the attempt leaves: the password was offered, and the callback
	// ran once. The library returns the disconnect without calling the callback again.
	s := &authState{cred: &credential{method: MethodPassword}, calls: 1, attempted: true, name: "password"}
	r := round{hosts: &hostCheck{}, auth: s}
	res := r.result(context.Background(), err, false)
	if res.Outcome != TransportFailure {
		t.Fatalf("outcome = %q, want transport failure: a server's disconnect is not a refusal; detail %q", res.Outcome, res.Detail)
	}
}
