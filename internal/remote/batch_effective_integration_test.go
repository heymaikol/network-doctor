//go:build integration

package remote

import (
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestBatchPinsWinOverUserConfiguration: a user's configuration sets every pinned option to
// the opposite of its pin, and the seven protections of this branch are set in a Match all
// block, which applies after the host block. OpenSSH must still resolve each option to the
// pinned value for a batch session, because the pins come first on the command line. This asks
// OpenSSH itself (ssh -G) for the effective values, so it checks what the connection will use.
func TestBatchPinsWinOverUserConfiguration(t *testing.T) {
	ssh := lookTool(t, "ssh", "")
	dir := t.TempDir()
	cfg := filepath.Join(dir, "config")
	config := `Host lab
  HostName 127.0.0.1
  BatchMode no
  PreferredAuthentications password,keyboard-interactive
  PasswordAuthentication yes
  AddKeysToAgent yes
  GSSAPIAuthentication yes
  PKCS11Provider /tmp/hostile.so
  IdentityAgent /tmp/hostile-agent.sock
  ForwardAgent yes
  ForwardX11 yes
  Tunnel yes
  ClearAllForwardings no
  LocalForward 127.0.0.1:1 127.0.0.1:9
  PermitLocalCommand yes
  LocalCommand /bin/true
  ControlMaster auto
  ControlPath /tmp/hostile-master.sock
  StrictHostKeyChecking accept-new
  UpdateHostKeys yes
  ProxyCommand /bin/false
Match all
  ForwardAgent yes
  ForwardX11 yes
  Tunnel yes
  ClearAllForwardings no
  LocalForward 127.0.0.1:1 127.0.0.1:9
  DynamicForward 127.0.0.1:2
  RemoteForward 127.0.0.1:3 127.0.0.1:9
  PermitLocalCommand yes
  LocalCommand /bin/true
  ControlMaster auto
  ControlPath /tmp/hostile-master.sock
  StrictHostKeyChecking accept-new
  UpdateHostKeys yes
`
	gssOK := gssKexListedBy(ssh)
	if !gssOK {
		// Without GSSAPI, OpenSSH rejects the GSSAPIAuthentication line as a bad option, so the
		// hostile line cannot take effect. That refusal is the check for it. The other pins are then
		// checked on the same configuration without the line.
		batchWrite(t, cfg, config, 0o600)
		out, err := exec.Command(ssh, "-G", "-F", cfg, "lab").CombinedOutput()
		if err == nil || !strings.Contains(strings.ToLower(string(out)), "bad configuration option: gssapiauthentication") {
			t.Fatalf("without GSSAPI, OpenSSH must refuse the GSSAPIAuthentication line: err %v, output %q", err, out)
		}
		config = strings.Replace(config, "  GSSAPIAuthentication yes\n", "", 1)
	}
	batchWrite(t, cfg, config, 0o600)

	args := []string{"-G", "-F", cfg}
	for _, pin := range batchOptions {
		args = append(args, "-o", pin)
	}
	out, err := exec.Command(ssh, append(args, "lab")...).Output()
	if err != nil {
		t.Fatalf("ssh -G: %v", err)
	}
	effective := map[string]string{}
	for _, line := range strings.Split(string(out), "\n") {
		if key, value, ok := strings.Cut(line, " "); ok {
			if _, seen := effective[key]; !seen {
				effective[key] = value
			}
		}
	}

	// Each expectation is the pinned value. An option that OpenSSH omits (none) is expected
	// to be absent, or to read none, and the hostile value must never appear.
	want := map[string]string{
		"batchmode":                "yes",
		"preferredauthentications": "publickey",
		"addkeystoagent":           "false",
		"identityagent":            "none",
		"forwardagent":             "no",
		"forwardx11":               "no",
		// Tunnel is off because ClearAllForwardings is on: OpenSSH clears the tunnel with the forwardings.
		"tunnel":                "false",
		"clearallforwardings":   "yes",
		"permitlocalcommand":    "no",
		"controlmaster":         "false",
		"stricthostkeychecking": "true",
		"updatehostkeys":        "false",
	}
	if gssOK {
		want["gssapiauthentication"] = "no"
	}
	for key, value := range want {
		if got := effective[key]; got != value {
			t.Errorf("effective %s = %q, want %q", key, got, value)
		}
	}
	for _, key := range []string{"controlpath", "proxycommand", "proxyjump", "pkcs11provider"} {
		if got, ok := effective[key]; ok && got != "none" {
			t.Errorf("effective %s = %q, the user's configuration leaked through a pin", key, got)
		}
	}
	for _, line := range strings.Split(string(out), "\n") {
		for _, key := range []string{"localforward ", "dynamicforward ", "remoteforward "} {
			if strings.HasPrefix(line, key) {
				t.Errorf("a forwarding from the user's configuration survived: %q", line)
			}
		}
	}
	if strings.Contains(effective["pubkeyacceptedalgorithms"], "sk-") {
		t.Errorf("security-key algorithms are offered: %q", effective["pubkeyacceptedalgorithms"])
	}
}

// gssKexListedBy reports whether the client lists a GSSAPI key exchange algorithm.
func gssKexListedBy(ssh string) bool {
	out, _ := exec.Command(ssh, "-Q", "kex-gss").CombinedOutput() // #nosec G204 -- fixed arguments
	for _, l := range strings.Split(string(out), "\n") {
		if strings.HasPrefix(strings.TrimSpace(l), "gss-") {
			return true
		}
	}
	return false
}
