package sshverify

import (
	"context"
	"errors"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// sample is the shape `ssh -G` prints, with the lines this package reads.
const sample = `user tester
hostname 127.0.0.1
port 2250
hostkeyalias alias-for-spike
identityfile ~/.ssh/id_rsa
identityfile /keys/%r.key
identityagent /run/agent.sock
userknownhostsfile /home/u/.ssh/known_hosts /home/u/.ssh/known_hosts2
globalknownhostsfile /etc/ssh/ssh_known_hosts /etc/ssh/extra
revokedhostkeys none
`

func TestParseConfigReadsTheResolvedValues(t *testing.T) {
	tg, err := parseConfig([]byte(sample), "/home/u")
	if err != nil {
		t.Fatal(err)
	}
	if tg.Host != "127.0.0.1" || tg.Port != 2250 || tg.User != "tester" {
		t.Errorf("host/port/user = %q %d %q", tg.Host, tg.Port, tg.User)
	}
	if tg.HostKeyAlias != "alias-for-spike" {
		t.Errorf("HostKeyAlias = %q", tg.HostKeyAlias)
	}
	if want := []string{filepath.Join("/home/u", ".ssh", "id_rsa"), "/keys/%r.key"}; !slices.Equal(tg.IdentityFile, want) {
		t.Errorf("IdentityFile = %q, want %q", tg.IdentityFile, want)
	}
	if want := []string{"/home/u/.ssh/known_hosts", "/home/u/.ssh/known_hosts2"}; !slices.Equal(tg.KnownHosts, want) {
		t.Errorf("KnownHosts = %q, want %q", tg.KnownHosts, want)
	}
	if len(tg.GlobalHosts) != 2 || tg.AgentSocket != "/run/agent.sock" || tg.AgentOff || tg.Unsupported != "" {
		t.Errorf("global=%q agent=%q off=%v unsupported=%q", tg.GlobalHosts, tg.AgentSocket, tg.AgentOff, tg.Unsupported)
	}
}

func TestParseConfigRefusesProxiedRoutes(t *testing.T) {
	for _, directive := range []string{"proxyjump bastion", "proxycommand nc %h %p"} {
		tg, err := parseConfig([]byte("user u\nhostname h\nport 22\nrevokedhostkeys none\nuserknownhostsfile none\nglobalknownhostsfile none\n"+directive+"\n"), "")
		if err != nil {
			t.Fatal(err)
		}
		if tg.Unsupported == "" {
			t.Errorf("%q: a proxied route must be marked unsupported", directive)
		}
	}
}

func TestParseConfigNoProxyIsNotUnsupported(t *testing.T) {
	tg, err := parseConfig([]byte("user u\nhostname h\nport 22\nrevokedhostkeys none\nuserknownhostsfile none\nglobalknownhostsfile none\nproxyjump none\nproxycommand none\n"), "")
	if err != nil {
		t.Fatal(err)
	}
	if tg.Unsupported != "" {
		t.Errorf("proxy set to none must not be unsupported, got %q", tg.Unsupported)
	}
}

func TestParseConfigIdentityAgentNoneDisablesTheAgent(t *testing.T) {
	tg, err := parseConfig([]byte("user u\nhostname h\nport 22\nrevokedhostkeys none\nuserknownhostsfile none\nglobalknownhostsfile none\nidentityagent none\n"), "")
	if err != nil {
		t.Fatal(err)
	}
	if !tg.AgentOff || tg.AgentSocket != "" {
		t.Errorf("identityagent none: off=%v socket=%q", tg.AgentOff, tg.AgentSocket)
	}
}

func TestParseConfigRejectsAnIncompleteListing(t *testing.T) {
	if _, err := parseConfig([]byte("hostname h\n"), ""); err == nil {
		t.Error("a listing without a user or port must be an error")
	}
}

// Resolve must pass the destination after -- so that a name starting with a
// dash is taken as a host, never as an option.
func TestResolveArgvEndsOptionsBeforeTheHost(t *testing.T) {
	var got []string
	saved := resolveOutput
	t.Cleanup(func() { resolveOutput = saved })
	resolveOutput = func(_ context.Context, args []string) ([]byte, error) {
		got = args
		return []byte(sample), nil
	}

	if _, err := Resolve(context.Background(), "-oProxyCommand=evil", 2250, "tester"); err != nil {
		t.Fatal(err)
	}
	want := []string{"-G", "-p", "2250", "-l", "tester", "--", "-oProxyCommand=evil"}
	if !slices.Equal(got, want) {
		t.Errorf("argv = %q, want %q", got, want)
	}
}

func TestResolveReportsConfigurationErrorsWithoutTheRoute(t *testing.T) {
	saved := resolveOutput
	t.Cleanup(func() { resolveOutput = saved })
	resolveOutput = func(context.Context, []string) ([]byte, error) {
		return nil, errors.New("Bad configuration option: nope")
	}

	_, err := Resolve(context.Background(), "host", 0, "")
	if err == nil || !strings.Contains(err.Error(), "could not read the SSH configuration") {
		t.Errorf("err = %v, want the configuration error named", err)
	}
}

// A configured revocation list is refused by the verification read, which cannot read it.
// An unset one is absent from the listing or printed as none, and neither refuses.
func TestParseConfigRefusesARevocationListOnly(t *testing.T) {
	base := "user u\nhostname h\nport 22\nuserknownhostsfile none\nglobalknownhostsfile none\n"
	if _, err := parseConfig([]byte(base+"revokedhostkeys /etc/ssh/revoked\n"), ""); err == nil || !strings.Contains(err.Error(), "RevokedHostKeys is set") {
		t.Errorf("a configured RevokedHostKeys was not refused: %v", err)
	}
	if _, err := parseConfig([]byte(base+"revokedhostkeys none\n"), ""); err != nil {
		t.Errorf("RevokedHostKeys none was refused: %v", err)
	}
	if _, err := parseConfig([]byte(base), ""); err != nil {
		t.Errorf("an unset RevokedHostKeys, omitted from the listing, was refused: %v", err)
	}
}

// none in a known-hosts keyword is no file, not a file named none. A path that only
// looks like it, such as ./none, is still a path.
func TestKnownHostsNoneIsNoFile(t *testing.T) {
	tg, err := parseConfig([]byte("user u\nhostname h\nport 22\nrevokedhostkeys none\nuserknownhostsfile none\nglobalknownhostsfile none\n"), "")
	if err != nil {
		t.Fatal(err)
	}
	if len(tg.KnownHosts) != 0 || len(tg.GlobalHosts) != 0 {
		t.Errorf("none read as files: user=%q global=%q", tg.KnownHosts, tg.GlobalHosts)
	}
	tg, err = parseConfig([]byte("user u\nhostname h\nport 22\nrevokedhostkeys none\nuserknownhostsfile ./none\nglobalknownhostsfile none\n"), "")
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(tg.KnownHosts, []string{"./none"}) {
		t.Errorf("./none is a path, got user=%q", tg.KnownHosts)
	}
}
