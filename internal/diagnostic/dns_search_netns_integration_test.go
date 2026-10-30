//go:build linux && netns_integration

package diagnostic

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
	"golang.org/x/sys/unix"
)

// Resolver configuration and hosts files belong only to the child mount and
// network namespaces. Every DNS exchange uses an in-memory connection.
func TestPublicDNSSearchIsolation(t *testing.T) {
	for _, ndots := range []string{"1", "5"} {
		for _, order := range []string{"files dns", "dns files"} {
			t.Run(ndots+"/"+order, func(t *testing.T) {
				cmd := exec.Command(os.Args[0], "-test.run=^TestPublicDNSSearchHelper$", "-test.v")
				cmd.Env = append(os.Environ(), "NETDOC_DNS_SEARCH_HELPER="+ndots, "NETDOC_DNS_HOSTS_ORDER="+order)
				cmd.SysProcAttr = &syscall.SysProcAttr{
					Cloneflags:                 unix.CLONE_NEWUSER | unix.CLONE_NEWNET | unix.CLONE_NEWNS,
					UidMappings:                []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getuid(), Size: 1}},
					GidMappings:                []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getgid(), Size: 1}},
					GidMappingsEnableSetgroups: false,
				}
				out, err := cmd.CombinedOutput()
				if errors.Is(err, syscall.EPERM) {
					skipOrRequireNetns(t, "user/mount/network namespaces unavailable")
				}
				if err != nil {
					t.Fatalf("isolated resolver fixture: %v\n%s", err, out)
				}
			})
		}
	}
}

func TestPublicDNSSearchHelper(t *testing.T) {
	ndots := os.Getenv("NETDOC_DNS_SEARCH_HELPER")
	if ndots == "" {
		t.Skip("runs in an isolated resolver namespace")
	}
	if err := unix.Mount("", "/", "", unix.MS_REC|unix.MS_PRIVATE, ""); err != nil {
		t.Fatal(err)
	}
	for path, contents := range map[string]string{
		"/etc/resolv.conf":   "nameserver 192.0.2.53\nsearch corp.example\noptions ndots:" + ndots + " attempts:1 timeout:1\n",
		"/etc/nsswitch.conf": "hosts: " + os.Getenv("NETDOC_DNS_HOSTS_ORDER") + "\n",
		"/etc/hosts":         "198.51.100.77 localprinter local.internal xn--bcher-kva.internal\n",
	} {
		file := filepath.Join(t.TempDir(), filepath.Base(path))
		if err := os.WriteFile(file, []byte(contents), 0600); err != nil {
			t.Fatal(err)
		}
		if err := unix.Mount(file, path, "", unix.MS_BIND, ""); err != nil {
			t.Fatal(err)
		}
	}
	for _, input := range []string{"server.internal", "server.internal.", "printer", "printer.", "bücher.example", "bücher.example.", ConnectivityProbeHost} {
		for _, outcome := range []struct{ partial, missing bool }{{}, {partial: true}, {missing: true}} {
			partial := outcome.partial
			t.Run(fmt.Sprintf("%s/partial=%t/missing=%t", input, partial, outcome.missing), func(t *testing.T) {
				target := mustTarget(t, input)
				var mu sync.Mutex
				var questions []string
				dial := func(ctx context.Context, _, _ string) (net.Conn, error) {
					conn := &publicDNSFixtureConn{splitDNSConn: &splitDNSConn{fixture: &splitDNSFixture{}}, mutate: func(reply []byte) []byte {
						name := searchQuestionName(reply)
						mu.Lock()
						questions = append(questions, name)
						mu.Unlock()
						if outcome.missing && name == strings.TrimSuffix(target.Host, ".")+"." {
							binary.BigEndian.PutUint16(reply[2:4], 0x8183)
							clear(reply[6:12])
							return reply[:lenQuestion(reply)]
						}
						if partial && binary.BigEndian.Uint16(reply[lenQuestion(reply)-4:]) == dnsTypeAAAA {
							return nil
						}
						return reply
					}}
					if partial {
						return lostDNSConn{conn, ctx}, nil
					}
					return conn, nil
				}
				ctx, cancel := context.WithTimeout(context.Background(), 80*time.Millisecond)
				defer cancel()
				ips, targets, err := lookupIPPublicWithDial(ctx, target.Host, dial, "8.8.8.8:53")
				mu.Lock()
				defer mu.Unlock()
				if !strings.Contains(target.Host, ".") {
					if len(questions) != 0 || len(targets) != 0 || len(ips) != 0 {
						t.Fatalf("short name disclosed: %v %v", questions, ips)
					}
					return
				}
				want := strings.TrimSuffix(target.Host, ".") + "."
				for _, question := range questions {
					if question != want {
						t.Errorf("public query %q, want only %q", question, want)
					}
				}
				if outcome.missing {
					if !dnsNotFound(err) || len(ips) != 0 {
						t.Fatalf("root NXDOMAIN accepted another name: %v %v", ips, err)
					}
				} else if err != nil || len(ips) == 0 {
					t.Fatalf("lookup: %v %v; questions=%v", ips, err, questions)
				}
			})
		}
	}
	for _, host := range []string{"localprinter", "localprinter.", "local.internal", "local.internal.", "xn--bcher-kva.internal", "xn--bcher-kva.internal."} {
		ips, _, err := lookupIPPublicWithDial(context.Background(), host, func(context.Context, string, string) (net.Conn, error) {
			return &publicDNSFixtureConn{splitDNSConn: &splitDNSConn{fixture: &splitDNSFixture{}}}, nil
		}, "8.8.8.8:53")
		if host == "localprinter" {
			if !errors.Is(err, errUnqualifiedPublicDNS) || len(ips) != 0 {
				t.Fatalf("relative local short name: %v %v", ips, err)
			}
			continue
		}
		if host == "localprinter." {
			if err != nil || len(ips) == 0 {
				t.Fatalf("absolute short name confused with relative hosts key: %v %v", ips, err)
			}
			continue
		}
		if !errors.Is(err, errHostsFileAnswer) || len(ips) != 0 {
			t.Errorf("hosts override %q: %v %v", host, ips, err)
		}
	}
	var names []string
	var mu sync.Mutex
	_, _, _ = lookupIPWithDial(context.Background(), "system.internal", func(context.Context, string, string) (net.Conn, error) {
		return &publicDNSFixtureConn{splitDNSConn: &splitDNSConn{fixture: &splitDNSFixture{}}, mutate: func(reply []byte) []byte {
			name := searchQuestionName(reply)
			mu.Lock()
			names = append(names, name)
			mu.Unlock()
			if name == "system.internal." {
				binary.BigEndian.PutUint16(reply[2:4], 0x8183)
				clear(reply[6:12])
				return reply[:lenQuestion(reply)]
			}
			return reply
		}}, nil
	})
	if !strings.Contains(strings.Join(names, ","), "system.internal.corp.example.") {
		t.Fatalf("system search disabled: %v", names)
	}
}

func lenQuestion(msg []byte) int {
	end, err := skipDNSName(msg, dnsHeaderLen)
	if err != nil {
		panic(err)
	}
	return end + 4
}

func searchQuestionName(msg []byte) string {
	var p dnsmessage.Parser
	if _, err := p.Start(msg); err != nil {
		panic(err)
	}
	q, err := p.Question()
	if err != nil {
		panic(err)
	}
	return q.Name.String()
}
