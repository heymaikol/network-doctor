//go:build linux

package app

import (
	"context"
	"os"
	"strings"
	"testing"
)

// echoProbe records whether echo is on at the first write, which is the prompt.
type echoProbe struct {
	t       *testing.T
	slave   *os.File
	written bool
	echo    bool
}

func (p *echoProbe) Write(b []byte) (int, error) {
	if !p.written {
		p.written = true
		p.echo = echoOn(p.t, p.slave)
	}
	return len(b), nil
}

// A key typed while the prompt shows is echoed unless echo is already off, so the
// prompt must be written with echo off. The probe reads the terminal at the write.
func TestPromptIsWrittenWithEchoOff(t *testing.T) {
	master, slave := openTerminal(t)
	defer master.Close()
	defer slave.Close()
	oldStdin, oldRead := os.Stdin, verifyReadPass
	os.Stdin = slave
	verifyReadPass = func() ([]byte, error) { return []byte("demo-password"), nil }
	t.Cleanup(func() { os.Stdin, verifyReadPass = oldStdin, oldRead })

	probe := &echoProbe{t: t, slave: slave}
	if _, err := readTerminalSecret(probe, "Password: "); err != nil {
		t.Fatalf("the secret was not read: %v", err)
	}
	if !probe.written {
		t.Fatal("the prompt was never written")
	}
	if probe.echo {
		t.Fatal("the prompt was written while echo was still on")
	}
	if !echoOn(t, slave) {
		t.Fatal("echo is still off after the prompt")
	}
}

// With -password-stdin on a terminal the secret is typed on that terminal, so it is
// read with echo off. The pipe is left unread: it is not the secret's source here.
func TestPasswordStdinOnATerminalIsReadWithEchoOff(t *testing.T) {
	master, slave := openTerminal(t)
	defer master.Close()
	defer slave.Close()
	oldStdin, oldRead, oldIn, oldTTY := os.Stdin, verifyReadPass, verifyStdin, verifyIsTTY
	os.Stdin = slave
	verifyReadPass = func() ([]byte, error) { return []byte("demo-password"), nil }
	verifyStdin = strings.NewReader("not-the-source\n")
	verifyIsTTY = func() bool { return true }
	t.Cleanup(func() { os.Stdin, verifyReadPass, verifyStdin, verifyIsTTY = oldStdin, oldRead, oldIn, oldTTY })

	probe := &echoProbe{t: t, slave: slave}
	if _, err := readVerifySecret(context.Background(), probe, "Password: ", true); err != nil {
		t.Fatalf("the secret was not read: %v", err)
	}
	if !probe.written || probe.echo {
		t.Fatalf("the -password-stdin secret on a terminal was read without a prompt, or with echo on (prompt written=%v, echo on=%v)", probe.written, probe.echo)
	}
}

// Ctrl-\ sends SIGQUIT. The default action ends the process without a defer, so
// the terminal kept echo off until the handler also covered quit.
func TestQuitDuringPasswordPromptRestoresEcho(t *testing.T) {
	_, echo := runSecretPrompt(t, []byte{0x1c}) // FS, the Ctrl-\ character
	if !echo {
		t.Fatal("echo is still off on the terminal after Ctrl-\\ at the password prompt")
	}
}
