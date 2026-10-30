//go:build linux && netns_integration

package supervisor

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// This runs real FRR 10.7.0 zebra and bgpd as supervisor-owned children. It is
// skipped unless NETDOC_FRR_STAGE names a private copy of an FRR install laid
// out as usr/ and runtime/usr/lib64 (never the evidence archive itself). It
// proves launch, attach, clean SIGTERM exit and reaping for one build. It does
// not prove isolation of FRR from the supervisor and says nothing about any
// other build.
func TestFRRRunsUnderTheSupervisor(t *testing.T) {
	stage := os.Getenv("NETDOC_FRR_STAGE")
	if stage == "" {
		t.Skip("NETDOC_FRR_STAGE not set")
	}
	frr := filepath.Join(stage, "usr", "libexec", "frr")
	for _, p := range []string{"zebra", "bgpd"} {
		if _, err := os.Stat(filepath.Join(frr, p)); err != nil { //nolint:gosec // G703: NETDOC_FRR_STAGE is the operator's own private copy.
			t.Fatalf("NETDOC_FRR_STAGE: %v", err)
		}
	}
	unshare, sh, mount := lookPath(t, "unshare"), lookPath(t, "sh"), lookPath(t, "mount")
	n := newNamespace(t)
	dir := t.TempDir()
	conf := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	zconf := conf("zebra.conf", "hostname r1\nline vty\n no login\n")
	bconf := conf("bgpd.conf", "router bgp 65001\n bgp router-id 1.1.1.1\n")
	env := []string{
		"LD_LIBRARY_PATH=" + strings.Join([]string{
			filepath.Join(stage, "usr", "lib64", "frr"),
			filepath.Join(stage, "usr", "lib64"),
			filepath.Join(stage, "runtime", "usr", "lib64"),
		}, ":"),
		"ASAN_OPTIONS=detect_leaks=0",
		"HOME=" + dir,
	}
	// FRR writes /var/tmp/frr/<daemon>.<pid>/ unconditionally. The supervisor
	// creates no mount namespace, so each launch gets a private one with a
	// tmpfs over /var/tmp. exec keeps the owned process identity.
	launch := func(name string, argv ...string) (*Child, string) {
		t.Helper()
		log := filepath.Join(dir, name+".log")
		f, err := os.Create(log) //nolint:gosec // G304: a log in this test's own TempDir.
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		wrapped := append([]string{unshare, "--mount", "--", sh, "-c", mount + ` -t tmpfs tmpfs /var/tmp && exec "$@"`, "sh"}, argv...)
		c, err := n.Start(context.Background(), Options{Argv: wrapped, Env: env, Stdout: f, Stderr: f})
		if err != nil {
			t.Fatalf("start %s: %v", name, err)
		}
		t.Cleanup(func() { _, _ = c.Stop(context.Background()) })
		return c, log
	}
	vty := []string{"--vty_socket", dir, "-P", "0", "-u", "root", "-g", "root"}
	zebra, zlog := launch("zebra", append([]string{filepath.Join(frr, "zebra"), "-f", zconf, "-i", filepath.Join(dir, "zebra.pid"), "-z", filepath.Join(dir, "zserv.api")}, vty...)...)
	bgpd, blog := launch("bgpd", append([]string{filepath.Join(frr, "bgpd"), "-f", bconf, "-i", filepath.Join(dir, "bgpd.pid"), "-z", filepath.Join(dir, "zserv.api")}, vty...)...)

	deadline := time.Now().Add(20 * time.Second)
	for _, sock := range []string{"zserv.api", "bgpd.vty"} {
		for {
			if _, err := os.Stat(filepath.Join(dir, sock)); err == nil {
				break
			}
			select {
			case <-zebra.Done():
				t.Fatalf("zebra exited early:\n%s", tail(zlog))
			case <-bgpd.Done():
				t.Fatalf("bgpd exited early:\n%s", tail(blog))
			default:
			}
			if time.Now().After(deadline) {
				t.Fatalf("no %s", sock)
			}
			time.Sleep(50 * time.Millisecond)
		}
	}

	// bgpd registered with zebra: ask zebra over its vty, as a third owned child.
	out := filepath.Join(dir, "vtysh.out")
	var seen bool
	for i := 0; i < 50 && !seen; i++ {
		f, err := os.Create(out) //nolint:gosec // G304: a capture in this test's own TempDir.
		if err != nil {
			t.Fatal(err)
		}
		v, err := n.Start(context.Background(), Options{
			Argv: []string{filepath.Join(stage, "usr", "bin", "vtysh"), "-H", "/dev/null", "--vty_socket", dir, "-c", "show zebra client"},
			Env:  env, Stdout: f, Stderr: f,
		})
		_ = f.Close()
		if err != nil {
			t.Fatal(err)
		}
		<-v.Done()
		if _, err := v.Stop(context.Background()); err != nil {
			t.Fatal(err)
		}
		b, _ := os.ReadFile(out) //nolint:gosec // G304: a capture in this test's own TempDir.
		seen = strings.Contains(string(b), "Client: bgp")
		if !seen {
			time.Sleep(100 * time.Millisecond)
		}
	}
	if !seen {
		t.Fatalf("zebra does not list bgpd as a client")
	}

	for name, c := range map[string]*Child{"bgpd": bgpd, "zebra": zebra} {
		select {
		case <-c.Done():
			t.Fatalf("%s exited before it was stopped", name)
		default:
		}
		pid := c.PID()
		st, err := c.Stop(context.Background())
		if err != nil || st.Code != 0 || st.Signal != 0 || st.Escalated {
			t.Fatalf("%s stop: %+v %v", name, st, err)
		}
		// The private mount namespace kept FRR's state out of the host.
		if _, err := os.Stat("/var/tmp/frr/" + name + "." + strconv.Itoa(pid)); err == nil {
			t.Fatalf("%s wrote to the host /var/tmp/frr", name)
		}
	}
	if err := n.Close(); err != nil {
		t.Fatal(err)
	}
	if !reaped() {
		t.Fatal("FRR children were not reaped")
	}
}

func tail(path string) string {
	b, _ := os.ReadFile(path) //nolint:gosec // G304: a log in this test's own TempDir.
	if len(b) > 1500 {
		b = b[len(b)-1500:]
	}
	return string(b)
}
