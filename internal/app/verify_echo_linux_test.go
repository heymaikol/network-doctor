//go:build linux

package app

import (
	"os"
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
