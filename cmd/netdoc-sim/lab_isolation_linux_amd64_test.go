package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"runtime"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"github.com/heymaikol/network-doctor/v2/internal/simulation"
	"golang.org/x/sys/unix"
)

// A fresh process makes this irreversible filter local to the test child. It
// kills attempted sockets (including netlink/interface queries), file opens
// (including resolv.conf, hosts and routing files), and subprocess execution.
// No network syscall reaches the kernel's network implementation.
func TestLabKernelIsolation(t *testing.T) {
	if mode := os.Getenv("NETDOC_LAB_ISOLATION_HELPER"); mode != "" {
		// The filter outlives this process, so anything the runtime defers to
		// exit runs under it. Coverage data emission is one such hook, and it
		// opens files, so refuse to filter a child that would attempt it.
		if dir := os.Getenv("GOCOVERDIR"); dir != "" {
			t.Fatalf("GOCOVERDIR=%s reached the isolated child: its exit hook writes coverage files the filter must kill", dir)
		}
		runtime.LockOSThread()
		blocked := [...]uint32{unix.SYS_SOCKET, unix.SYS_SOCKETPAIR, unix.SYS_CONNECT, unix.SYS_OPEN, unix.SYS_CREAT, unix.SYS_OPENAT, unix.SYS_OPENAT2, unix.SYS_EXECVE, unix.SYS_EXECVEAT}
		// One load, two instructions per blocked call, one final allow. The
		// array makes that a constant, so the program length seccomp is handed
		// is a constant too rather than a narrowed slice length.
		const programLen = 2 + 2*len(blocked)
		filter := make([]unix.SockFilter, 0, programLen)
		filter = append(filter, unix.SockFilter{Code: unix.BPF_LD | unix.BPF_W | unix.BPF_ABS, K: 0})
		for _, nr := range blocked {
			filter = append(filter, unix.SockFilter{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, K: nr, Jf: 1}, unix.SockFilter{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_KILL_PROCESS})
		}
		filter = append(filter, unix.SockFilter{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_ALLOW})
		if len(filter) != programLen {
			t.Fatalf("seccomp program is %d instructions, want %d", len(filter), programLen)
		}
		program := unix.SockFprog{Len: uint16(programLen), Filter: &filter[0]}
		if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
			t.Fatal(err)
		}
		// #nosec G103 -- seccomp(2) takes the filter program by pointer, so
		// installing one requires the address of this stack-local SockFprog.
		// It stays live across the call, which returns before this returns.
		_, _, errno := unix.RawSyscall(unix.SYS_SECCOMP, unix.SECCOMP_SET_MODE_FILTER, unix.SECCOMP_FILTER_FLAG_TSYNC, uintptr(unsafe.Pointer(&program)))
		if errno != 0 {
			t.Fatal(errno)
		}
		switch mode {
		case "socket":
			_, _ = unix.Socket(unix.AF_INET, unix.SOCK_STREAM, 0)
		case "file":
			_, _ = os.Open("/etc/resolv.conf")
		case "fuzz":
			summary, err := simulation.RunLabFuzz(context.Background(), simulation.LabFuzzOptions{Seed: 847293, Cases: 32, MaxFaults: 4, Workers: 2, TwoSided: true})
			if err != nil {
				os.Exit(3)
			}
			if err := json.NewEncoder(os.Stdout).Encode(summary); err != nil {
				os.Exit(3)
			}
			os.Exit(0)
		case "lab":
			os.Exit(run([]string{"lab", "run", "--all", "--json"}, os.Stdout, os.Stderr))
		}
		os.Exit(99) // forbidden operation unexpectedly survived
	}
	for _, mode := range []string{"lab", "fuzz", "socket", "file"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			// #nosec G204 G702 -- the child is this same test binary, os.Args[0],
			// re-run with a literal -test.run filter. The helper mode it
			// takes travels in the environment below, not in an argument.
			cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestLabKernelIsolation$")
			// Set these before startup: Go CPU polling and glibc's lazy malloc
			// arena sizing can otherwise open CPU topology files after filtering.
			// go test -cover exports GOCOVERDIR so subprocesses emit coverage
			// too. That emission is an openat from a runtime exit hook, long
			// after the filter is installed, and the child's counters duplicate
			// the in-process rerun below, so drop the variable.
			env := slices.DeleteFunc(os.Environ(), func(kv string) bool { return strings.HasPrefix(kv, "GOCOVERDIR=") })
			cmd.Env = append(env, "GOMAXPROCS=2", "MALLOC_ARENA_MAX=2", "NETDOC_LAB_ISOLATION_HELPER="+mode, "HTTPS_PROXY=http://unresolvable.invalid:1", "ALL_PROXY=socks5://unresolvable.invalid:1")
			var out, errOut bytes.Buffer
			cmd.Stdout = &out
			cmd.Stderr = &errOut
			err := cmd.Run()
			if mode == "fuzz" {
				if err != nil {
					t.Fatalf("isolated fuzzer: %v %s", err, errOut.String())
				}
				summary, err := simulation.RunLabFuzz(context.Background(), simulation.LabFuzzOptions{Seed: 847293, Cases: 32, MaxFaults: 4, Workers: 2, TwoSided: true})
				if err != nil {
					t.Fatal(err)
				}
				var ordinary bytes.Buffer
				if err := json.NewEncoder(&ordinary).Encode(summary); err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(out.Bytes(), ordinary.Bytes()) {
					t.Fatal("kernel isolation changed fuzz report")
				}
			} else if mode == "lab" {
				if cmd.ProcessState.ExitCode() != exitOK || !bytes.Contains(out.Bytes(), []byte(`"Scenario": "tls-http-no-response"`)) {
					t.Fatalf("isolated lab: %v %s", err, errOut.String())
				}
				var ordinary bytes.Buffer
				if code := run([]string{"lab", "run", "--all", "--json"}, &ordinary, &errOut); code != exitOK || !bytes.Equal(out.Bytes(), ordinary.Bytes()) {
					t.Fatal("kernel isolation changed serialized evidence")
				}
			} else if cmd.ProcessState.Sys().(syscall.WaitStatus).Signal() != syscall.SIGSYS {
				t.Fatalf("negative control was not killed: %v %s", err, errOut.String())
			}
		})
	}
}
