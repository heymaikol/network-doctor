//go:build linux

package capture

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

const (
	uuid = "0f8b6c1e-5d2a-4b7e-9c3f-1a2b3c4d5e6f"
	// streamBody carries every kind of claim a producer could make. None of them
	// may influence the snapshot.
	streamBody = `{"authenticated":true,"sha256":"00000000000000000000000000000000000000000000000000000000000000ff","pid":1,"netns_inode":4026531840,"uuid":"` + uuid + `"}` + "\n"
	forgedBody = `{"forged":true}` + "\n"

	requireEnv = "NETDOC_SIM_REQUIRE_NETNS"
)

func stream(r Role) string { return string(r) + "." + uuid + ".jsonl" }

// unavailable ends a test whose host cannot run it: a skip, or a failure where a
// gated job declared the host must.
func unavailable(t *testing.T, format string, args ...any) {
	t.Helper()
	if os.Getenv(requireEnv) != "" {
		t.Fatalf("%s is set but the host cannot run this test: "+format, append([]any{requireEnv}, args...)...)
	}
	t.Skipf(format, args...)
}

func code(err error) Code {
	var r *Refusal
	if errors.As(err, &r) {
		return r.Code()
	}
	return ""
}

func inboxFor(t *testing.T, role Role) *Inbox {
	t.Helper()
	in, err := NewInbox(role)
	if code(err) == FilesystemRefused {
		unavailable(t, "temporary directory is not on a filesystem the lease proof accepts")
	}
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := in.Close(); err != nil {
			t.Errorf("cleanup Close: %v", err)
		}
	})
	return in
}

func put(t *testing.T, in *Inbox, name, body string) string {
	t.Helper()
	p := filepath.Join(in.Path(), name)
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil { //nolint:gosec // G306: the file stands in for a producer's 0600 stream.
		t.Fatal(err)
	}
	return p
}

func seal(t *testing.T, in *Inbox) (*Snapshot, error) {
	t.Helper()
	s, err := in.Seal(context.Background())
	if s != nil {
		t.Cleanup(func() { _ = s.Close() })
	}
	return s, err
}

func mustSeal(t *testing.T, in *Inbox) *Snapshot {
	t.Helper()
	s, err := seal(t, in)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	return s
}

// refused requires a Refusal with the given code whose text names nothing the
// producer controls.
func refused(t *testing.T, err error, want Code, hostile ...string) {
	t.Helper()
	if got := code(err); got != want {
		t.Fatalf("got %v (%q), want code %s", err, got, want)
	}
	msg := err.Error()
	if len(msg) > MaxDiagnosticBytes {
		t.Fatalf("diagnostic is %d bytes: %q", len(msg), msg)
	}
	for _, h := range append(hostile, "/tmp", os.TempDir(), uuid, "errno") {
		if h != "" && strings.Contains(msg, h) {
			t.Fatalf("diagnostic %q leaks %q", msg, h)
		}
	}
}

func fdCount(t *testing.T) int {
	t.Helper()
	e, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	return len(e)
}

// writable reports whether a non-blocking write open of path succeeds now. A lease
// that leaked would make it fail with EWOULDBLOCK.
func writable(path string) error {
	fd, err := unix.Open(path, unix.O_WRONLY|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err == nil {
		_ = unix.Close(fd)
	}
	return err
}

func read(t *testing.T, s *Snapshot) string {
	t.Helper()
	b := make([]byte, s.Size())
	if n, err := s.ReadAt(b, 0); n != len(b) || (err != nil && !errors.Is(err, io.EOF)) {
		t.Fatalf("ReadAt: %d %v", n, err)
	}
	return string(b)
}

func TestSealCopiesAndHashesTheSealedBytes(t *testing.T) {
	in := inboxFor(t, BGPD)
	put(t, in, stream(BGPD), streamBody)
	s := mustSeal(t, in)
	if want := sha256.Sum256([]byte(streamBody)); s.SHA256() != want {
		t.Fatalf("digest %x, want the hash of the bytes, not the claimed one: %x", s.SHA256(), want)
	}
	if s.Size() != int64(len(streamBody)) || read(t, s) != streamBody {
		t.Fatal("snapshot bytes differ")
	}
	p := make([]byte, 8)
	if n, err := s.ReadAt(p, s.Size()-4); n != 4 || !errors.Is(err, io.EOF) {
		t.Fatalf("tail read: %d %v", n, err)
	}
	if n, err := s.ReadAt(p, s.Size()+10); n != 0 || !errors.Is(err, io.EOF) {
		t.Fatalf("read past end: %d %v", n, err)
	}
}

func TestSnapshotIsImmutable(t *testing.T) {
	in := inboxFor(t, Zebra)
	src := put(t, in, stream(Zebra), streamBody)
	s := mustSeal(t, in)
	// Every way a producer can still touch the source leaves the copy alone.
	if err := os.WriteFile(src, []byte("overwritten"), 0o600); err != nil { //nolint:gosec // G306: stands in for a producer.
		t.Fatal(err)
	}
	if err := os.Truncate(src, 0); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(put(t, in, "other", forgedBody), src); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(src); err != nil {
		t.Fatal(err)
	}
	if read(t, s) != streamBody {
		t.Fatal("snapshot followed the source")
	}
	// A writable open of the anonymous file is allowed by the kernel, so only the
	// seals stand between it and the bytes.
	alias := fmt.Sprintf("/proc/self/fd/%d", s.f.Fd())
	w, err := unix.Open(alias, unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatalf("reopen through /proc: %v", err)
	}
	defer func() { _ = unix.Close(w) }()
	if _, err := unix.Write(w, []byte("x")); !errors.Is(err, unix.EPERM) {
		t.Fatalf("write to sealed copy: %v", err)
	}
	if err := unix.Ftruncate(w, 0); !errors.Is(err, unix.EPERM) {
		t.Fatalf("truncate sealed copy: %v", err)
	}
	if _, err := unix.Mmap(w, 0, 1, unix.PROT_WRITE, unix.MAP_SHARED); !errors.Is(err, unix.EPERM) {
		t.Fatalf("writable map of sealed copy: %v", err)
	}
	if _, err := unix.FcntlInt(uintptr(w), unix.F_ADD_SEALS, unix.F_SEAL_FUTURE_WRITE); !errors.Is(err, unix.EPERM) {
		t.Fatalf("seals are not themselves sealed: %v", err)
	}
	if read(t, s) != streamBody {
		t.Fatal("sealed copy changed")
	}
}

func TestSealRefusesWhatIsNotExactlyOneRoleStream(t *testing.T) {
	outside := func(t *testing.T) string {
		p := filepath.Join(t.TempDir(), "secret")
		if err := os.WriteFile(p, []byte("outside"), 0o600); err != nil { //nolint:gosec // G306: a file outside the inbox.
			t.Fatal(err)
		}
		return p
	}
	cases := []struct {
		name  string
		setup func(t *testing.T, in *Inbox)
		want  Code
	}{
		{"empty", func(*testing.T, *Inbox) {}, UnexpectedEntry},
		{"other role's stream", func(t *testing.T, in *Inbox) { put(t, in, stream(Zebra), streamBody) }, UnexpectedEntry},
		{"partial", func(t *testing.T, in *Inbox) { put(t, in, stream(BGPD)+".partial", streamBody) }, UnexpectedEntry},
		{"failure marker beside the stream", func(t *testing.T, in *Inbox) {
			put(t, in, stream(BGPD), streamBody)
			put(t, in, stream(BGPD)+".failed", "")
		}, UnexpectedEntry},
		{"unrelated file beside the stream", func(t *testing.T, in *Inbox) {
			put(t, in, stream(BGPD), streamBody)
			put(t, in, "notes", "x")
		}, UnexpectedEntry},
		{"uppercase uuid", func(t *testing.T, in *Inbox) {
			put(t, in, "bgpd."+strings.ToUpper(uuid)+".jsonl", streamBody)
		}, UnexpectedEntry},
		{"hostile name", func(t *testing.T, in *Inbox) { put(t, in, "\x1b[31mHOSTILE\nname", streamBody) }, UnexpectedEntry},
		{"two epochs", func(t *testing.T, in *Inbox) {
			put(t, in, stream(BGPD), streamBody)
			put(t, in, "bgpd.1f8b6c1e-5d2a-4b7e-9c3f-1a2b3c4d5e6f.jsonl", streamBody)
		}, MixedEpochs},
		{"directory", func(t *testing.T, in *Inbox) {
			if err := os.Mkdir(filepath.Join(in.Path(), stream(BGPD)), 0o700); err != nil {
				t.Fatal(err)
			}
		}, NotRegular},
		{"symlink to a regular file", func(t *testing.T, in *Inbox) {
			if err := os.Symlink(outside(t), filepath.Join(in.Path(), stream(BGPD))); err != nil {
				t.Fatal(err)
			}
		}, LinkRefused},
		{"dangling symlink", func(t *testing.T, in *Inbox) {
			if err := os.Symlink("/nonexistent", filepath.Join(in.Path(), stream(BGPD))); err != nil {
				t.Fatal(err)
			}
		}, LinkRefused},
		{"fifo", func(t *testing.T, in *Inbox) {
			if err := unix.Mkfifo(filepath.Join(in.Path(), stream(BGPD)), 0o600); err != nil {
				t.Fatal(err)
			}
		}, NotRegular},
		{"socket", func(t *testing.T, in *Inbox) { // a socket node needs no socket, and the ordinary suite stays off the host
			if err := unix.Mknod(filepath.Join(in.Path(), stream(BGPD)), unix.S_IFSOCK|0o600, 0); err != nil {
				t.Fatal(err)
			}
		}, NotRegular},
		{"hard link to a file outside", func(t *testing.T, in *Inbox) {
			if err := os.Link(outside(t), filepath.Join(in.Path(), stream(BGPD))); err != nil {
				t.Fatal(err)
			}
		}, LinkRefused},
		{"too many entries", func(t *testing.T, in *Inbox) {
			for i := 0; i <= maxEntries; i++ {
				put(t, in, "f"+strconv.Itoa(i), "x")
			}
			t.Cleanup(func() { _ = in.Close() }) // one bounded pass leaves the ninth entry; the registered cleanup finishes
		}, ResourceLimit},
		{"larger than the cap", func(t *testing.T, in *Inbox) {
			put(t, in, stream(BGPD), "")
			if err := os.Truncate(filepath.Join(in.Path(), stream(BGPD)), MaxStreamBytes+1); err != nil {
				t.Fatal(err)
			}
		}, ResourceLimit},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := inboxFor(t, BGPD)
			tc.setup(t, in)
			before := fdCount(t)
			done := make(chan error, 1)
			go func() { _, err := in.Seal(context.Background()); done <- err }()
			select {
			case err := <-done:
				refused(t, err, tc.want, "HOSTILE")
			case <-time.After(5 * time.Second):
				t.Fatal("Seal blocked")
			}
			if after := fdCount(t); after != before {
				t.Fatalf("descriptors %d before, %d after a refusal", before, after)
			}
		})
	}
}

func TestSealRefusesAWriterThatIsStillOpen(t *testing.T) {
	t.Run("descriptor", func(t *testing.T) {
		in := inboxFor(t, BGPD)
		w, err := os.OpenFile(put(t, in, stream(BGPD), streamBody), os.O_WRONLY|os.O_APPEND, 0) //nolint:gosec // G304: a path in this test's own inbox.
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = w.Close() }()
		_, err = in.Seal(context.Background())
		refused(t, err, WriterPresent)
	})
	t.Run("mapping outlives the descriptor", func(t *testing.T) {
		in := inboxFor(t, BGPD)
		p := put(t, in, stream(BGPD), strings.Repeat("a", 4096))
		w, err := os.OpenFile(p, os.O_RDWR, 0) //nolint:gosec // G304: a path in this test's own inbox.
		if err != nil {
			t.Fatal(err)
		}
		m, err := unix.Mmap(int(w.Fd()), 0, 4096, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
		if err != nil {
			t.Fatal(err)
		}
		_ = w.Close() // the descriptor is gone; the writable alias is not
		_, err = in.Seal(context.Background())
		refused(t, err, WriterPresent)
		m[0] = 'b' // still writable, which is the point
		if err := unix.Munmap(m); err != nil {
			t.Fatal(err)
		}
		in2 := inboxFor(t, BGPD)
		put(t, in2, stream(BGPD), streamBody)
		mustSeal(t, in2) // the same shape without the alias is accepted
	})
	t.Run("a writer arrives between the listing and the lease", func(t *testing.T) {
		in := inboxFor(t, BGPD)
		p := put(t, in, stream(BGPD), streamBody)
		var w *os.File
		in.afterList = func() {
			var err error
			if w, err = os.OpenFile(p, os.O_WRONLY, 0); err != nil { //nolint:gosec // G304: a path in this test's own inbox.
				t.Error(err)
			}
		}
		_, err := in.Seal(context.Background())
		if w != nil {
			_ = w.Close()
		}
		refused(t, err, WriterPresent)
	})
}

// A producer that exits cleanly can leave a descendant, in another session, that
// still holds the writable descriptor. The group kill the supervisor performs
// cannot see it; the lease can.
func TestSealRefusesAnEscapedWriterAfterTheProducerExited(t *testing.T) {
	for _, killFirst := range []bool{false, true} {
		t.Run(fmt.Sprintf("killed first=%v", killFirst), func(t *testing.T) {
			in := inboxFor(t, BGPD)
			path := filepath.Join(in.Path(), stream(BGPD))
			pidfile := filepath.Join(t.TempDir(), "pid")
			cmd := exec.Command(os.Args[0]) //nolint:gosec // G204: re-executes this test binary.
			cmd.Env = []string{"CAPTURE_HELPER=detach", "CAPTURE_FILE=" + path, "CAPTURE_PIDFILE=" + pidfile}
			if err := cmd.Run(); err != nil {
				t.Fatalf("producer: %v", err)
			}
			raw, err := os.ReadFile(pidfile) //nolint:gosec // G304: the path is this test's own TempDir.
			if err != nil {
				t.Fatal(err)
			}
			pid, _ := strconv.Atoi(string(raw))
			t.Cleanup(func() { _ = unix.Kill(pid, unix.SIGKILL) })
			if killFirst {
				if err := unix.Kill(pid, unix.SIGKILL); err != nil {
					t.Fatal(err)
				}
				waitForNoWriter(t, path)
				mustSeal(t, in)
				return
			}
			_, err = in.Seal(context.Background())
			refused(t, err, WriterPresent)
		})
	}
}

// waitForNoWriter polls with a throwaway lease until the killed process's
// descriptors are gone, so the next Seal is not racing the kernel's teardown.
func waitForNoWriter(t *testing.T, path string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
		if err != nil {
			t.Fatal(err)
		}
		_, err = unix.FcntlInt(uintptr(fd), unix.F_SETLEASE, unix.F_RDLCK)
		_, _ = unix.FcntlInt(uintptr(fd), unix.F_SETLEASE, unix.F_UNLCK)
		_ = unix.Close(fd)
		if err == nil {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("killed writer still holds the stream")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestSealDetectsChangesWhileItReads(t *testing.T) {
	forge := func(t *testing.T, in *Inbox, p string) {
		if err := os.Rename(put(t, in, "forged", forgedBody), p); err != nil {
			t.Error(err)
		}
	}
	cases := []struct {
		name string
		hook func(t *testing.T, in *Inbox, p string) // runs after the copy
		list func(t *testing.T, in *Inbox, p string) // runs after the listing
		want Code
	}{
		{name: "replaced after the copy", hook: forge, want: Modified},
		{name: "removed after the copy", hook: func(t *testing.T, _ *Inbox, p string) { _ = os.Remove(p) }, want: Modified},
		{name: "linked outside then replaced after the copy", hook: func(t *testing.T, in *Inbox, p string) {
			if err := os.Link(p, filepath.Join(t.TempDir(), "alias")); err != nil {
				t.Error(err)
			}
			forge(t, in, p)
		}, want: Modified},
		{name: "write open attempted while leased", hook: func(t *testing.T, _ *Inbox, p string) {
			if err := writable(p); !errors.Is(err, unix.EWOULDBLOCK) {
				t.Errorf("write open under lease: %v", err)
			}
		}, want: Modified},
		{name: "second link added", hook: func(t *testing.T, in *Inbox, p string) {
			if err := os.Link(p, filepath.Join(in.Path(), "alias")); err != nil {
				t.Error(err)
			}
		}, want: Modified},
		{name: "mode changed", hook: func(t *testing.T, _ *Inbox, p string) {
			if err := os.Chmod(p, 0o640); err != nil { //nolint:gosec // G302: the mode change is the event under test.
				t.Error(err)
			}
		}, want: Modified},
		{name: "times changed", hook: func(t *testing.T, _ *Inbox, p string) {
			if err := os.Chtimes(p, time.Unix(1, 0), time.Unix(1, 0)); err != nil {
				t.Error(err)
			}
		}, want: Modified},
		{name: "entry added", hook: func(t *testing.T, in *Inbox, _ string) { put(t, in, stream(BGPD)+".failed", "") }, want: Modified},
		{name: "replaced after the listing", list: forge, want: Modified},
		{name: "removed after the listing", list: func(t *testing.T, _ *Inbox, p string) { _ = os.Remove(p) }, want: Modified},
		{name: "symlink swapped in after the listing", list: func(t *testing.T, _ *Inbox, p string) {
			_ = os.Remove(p)
			if err := os.Symlink("/etc/hostname", p); err != nil {
				t.Error(err)
			}
		}, want: LinkRefused},
		{name: "fifo swapped in after the listing", list: func(t *testing.T, _ *Inbox, p string) {
			_ = os.Remove(p)
			if err := unix.Mkfifo(p, 0o600); err != nil {
				t.Error(err)
			}
		}, want: NotRegular},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := inboxFor(t, BGPD)
			p := put(t, in, stream(BGPD), streamBody)
			if tc.hook != nil {
				in.afterCopy = func() { tc.hook(t, in, p) }
			}
			if tc.list != nil {
				in.afterList = func() { tc.list(t, in, p) }
			}
			before := fdCount(t)
			s, err := in.Seal(context.Background())
			refused(t, err, tc.want)
			if s != nil {
				t.Fatal("refusal returned a snapshot")
			}
			if after := fdCount(t); after != before {
				t.Fatalf("descriptors %d before, %d after", before, after)
			}
			if tc.name != "removed after the copy" && tc.list == nil {
				if err := writable(p); err != nil && !errors.Is(err, unix.ENOENT) {
					t.Fatalf("lease outlived the refusal: %v", err)
				}
			}
		})
	}
}

func TestSealReleasesItsLeaseOnSuccess(t *testing.T) {
	in := inboxFor(t, BGPD)
	p := put(t, in, stream(BGPD), streamBody)
	mustSeal(t, in)
	if err := writable(p); err != nil {
		t.Fatalf("lease outlived Seal: %v", err)
	}
}

func TestSealIsOneShot(t *testing.T) {
	t.Run("a second seal", func(t *testing.T) {
		in := inboxFor(t, BGPD)
		put(t, in, stream(BGPD), streamBody)
		first := mustSeal(t, in)
		_, err := in.Seal(context.Background())
		refused(t, err, AlreadyUsed)
		if read(t, first) != streamBody {
			t.Fatal("first snapshot changed")
		}
	})
	t.Run("a restarted producer cannot be spliced in", func(t *testing.T) {
		in := inboxFor(t, BGPD)
		p := put(t, in, stream(BGPD), streamBody)
		first := mustSeal(t, in)
		if err := os.Remove(p); err != nil {
			t.Fatal(err)
		}
		put(t, in, "bgpd.2f8b6c1e-5d2a-4b7e-9c3f-1a2b3c4d5e6f.jsonl", forgedBody)
		_, err := in.Seal(context.Background())
		refused(t, err, AlreadyUsed)
		if read(t, first) != streamBody {
			t.Fatal("first snapshot changed")
		}
	})
	t.Run("a refusal consumes the inbox", func(t *testing.T) {
		in := inboxFor(t, BGPD)
		_, err := in.Seal(context.Background())
		refused(t, err, UnexpectedEntry)
		put(t, in, stream(BGPD), streamBody) // fixed afterwards
		_, err = in.Seal(context.Background())
		refused(t, err, AlreadyUsed)
	})
	t.Run("a cancelled seal", func(t *testing.T) {
		in := inboxFor(t, BGPD)
		put(t, in, stream(BGPD), streamBody)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_, err := in.Seal(ctx)
		refused(t, err, Cancelled)
		_, err = in.Seal(context.Background())
		refused(t, err, AlreadyUsed)
	})
	t.Run("after close", func(t *testing.T) {
		in := inboxFor(t, BGPD)
		if err := in.Close(); err != nil {
			t.Fatal(err)
		}
		_, err := in.Seal(context.Background())
		refused(t, err, Closed)
	})
}

// This covers a context cancelled after the listing and before any byte is
// copied. TestSealStopsWhenCancelledAfterACopiedChunk covers cancellation once
// the copy has started.
func TestSealStopsWhenCancelledBeforeTheCopy(t *testing.T) {
	in := inboxFor(t, BGPD)
	p := put(t, in, stream(BGPD), "")
	if err := os.Truncate(p, 3*chunkBytes); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	in.afterList = cancel
	chunks := 0
	in.afterChunk = func() { chunks++ }
	before := fdCount(t)
	_, err := in.Seal(ctx)
	refused(t, err, Cancelled)
	if chunks != 0 {
		t.Fatalf("copied %d chunks after the context was cancelled", chunks)
	}
	if after := fdCount(t); after != before {
		t.Fatalf("descriptors %d before, %d after", before, after)
	}
	if err := writable(p); err != nil {
		t.Fatalf("lease outlived a cancelled seal: %v", err)
	}
}

// The context is cancelled after the first chunk reached the sealed copy. The
// copy must stop at the next chunk boundary, release the partial memfd and the
// lease, and return no Snapshot.
func TestSealStopsWhenCancelledAfterACopiedChunk(t *testing.T) {
	in := inboxFor(t, BGPD)
	p := put(t, in, stream(BGPD), "")
	if err := os.Truncate(p, 3*chunkBytes); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	chunks := 0
	in.afterChunk = func() {
		chunks++
		if chunks == 1 {
			cancel()
		}
	}
	before := fdCount(t)
	s, err := in.Seal(ctx)
	refused(t, err, Cancelled)
	if s != nil {
		t.Fatal("cancelled seal returned a snapshot")
	}
	if chunks != 1 {
		t.Fatalf("%d chunks were copied; the copy must stop after the first", chunks)
	}
	if after := fdCount(t); after != before {
		t.Fatalf("partial copy leaked descriptors: %d before, %d after", before, after)
	}
	if err := writable(p); err != nil {
		t.Fatalf("lease outlived a cancelled seal: %v", err)
	}
}

func TestSealEnforcesTheSizeCap(t *testing.T) {
	for _, tc := range []struct {
		size int
		want Code
	}{{1024, ""}, {1025, ResourceLimit}} {
		in := inboxFor(t, BGPD)
		in.maxBytes = 1024
		put(t, in, stream(BGPD), strings.Repeat("x", tc.size))
		s, err := seal(t, in)
		if tc.want == "" && (err != nil || s.Size() != 1024) {
			t.Fatalf("at the cap: %v", err)
		}
		if tc.want != "" {
			refused(t, err, tc.want)
		}
	}
}

func TestSealRefusesAStreamOwnedBySomeoneElse(t *testing.T) {
	in := inboxFor(t, BGPD)
	put(t, in, stream(BGPD), streamBody)
	in.euid++ // no unprivileged test can chown, so the collector's idea of its user moves instead
	_, err := in.Seal(context.Background())
	refused(t, err, OwnerRefused)
}

func TestSealOnlyTrustsFilesystemsWhoseWritersItCanSee(t *testing.T) {
	statfsAs := func(magic int64) func(int, *unix.Statfs_t) error {
		// Type is int32 on some architectures; SetInt truncates like the kernel's value does.
		return func(_ int, st *unix.Statfs_t) error { reflect.ValueOf(&st.Type).Elem().SetInt(magic); return nil }
	}
	for name, magic := range map[string]int64{"overlayfs": 0x794c7630, "fuse": 0x65735546, "nfs": 0x6969, "smb2": 0xfe534d42, "9p": 0x01021997, "unknown": 0} {
		t.Run(name, func(t *testing.T) {
			if _, err := newInbox2(t, statfsAs(magic)); code(err) != FilesystemRefused {
				t.Fatalf("new inbox on %s: %v", name, err)
			}
			in := inboxFor(t, BGPD)
			put(t, in, stream(BGPD), streamBody)
			in.statfs = statfsAs(magic)
			_, err := in.Seal(context.Background())
			refused(t, err, FilesystemRefused)
		})
	}
	for name, magic := range map[string]int64{"tmpfs": unix.TMPFS_MAGIC, "ext4": unix.EXT4_SUPER_MAGIC, "btrfs": unix.BTRFS_SUPER_MAGIC, "xfs": unix.XFS_SUPER_MAGIC} {
		t.Run(name, func(t *testing.T) {
			in, err := newInbox2(t, statfsAs(magic))
			if err != nil {
				t.Fatalf("%s refused: %v", name, err)
			}
			put(t, in, stream(BGPD), streamBody)
			mustSeal(t, in)
		})
	}
}

// newInbox2 builds an inbox with a fake statfs and registers its cleanup.
func newInbox2(t *testing.T, statfs func(int, *unix.Statfs_t) error) (*Inbox, error) {
	t.Helper()
	in, err := newInbox(BGPD, statfs)
	if in != nil {
		t.Cleanup(func() { _ = in.Close() })
	}
	return in, err
}

func TestInboxesAreDistinctPrivateAndEmpty(t *testing.T) {
	a, b := inboxFor(t, BGPD), inboxFor(t, Zebra)
	if a.Path() == b.Path() || strings.HasPrefix(a.Path(), b.Path()+"/") || strings.HasPrefix(b.Path(), a.Path()+"/") {
		t.Fatalf("inboxes overlap: %q %q", a.Path(), b.Path())
	}
	if a.dev == b.dev && a.ino == b.ino {
		t.Fatal("inboxes are one directory")
	}
	for _, in := range []*Inbox{a, b} {
		var st unix.Stat_t
		if err := unix.Fstat(int(in.dir.Fd()), &st); err != nil {
			t.Fatal(err)
		}
		if st.Mode&0o777 != 0o700 || int(st.Uid) != os.Geteuid() || st.Nlink != 2 {
			t.Fatalf("inbox is mode %o uid %d nlink %d", st.Mode&0o777, st.Uid, st.Nlink)
		}
		if names, _ := os.ReadDir(in.Path()); len(names) != 0 {
			t.Fatal("new inbox is not empty")
		}
		if flags, err := unix.FcntlInt(in.dir.Fd(), unix.F_GETFD, 0); err != nil || flags&unix.FD_CLOEXEC == 0 {
			t.Fatalf("directory descriptor is inheritable: %v", err)
		}
	}
	if _, err := NewInbox("kernel"); code(err) != InvalidRole {
		t.Fatalf("unknown role: %v", err)
	}
	// Each role accepts only its own stream name.
	put(t, a, stream(Zebra), streamBody)
	_, err := a.Seal(context.Background())
	refused(t, err, UnexpectedEntry)
}

func TestEveryDescriptorIsCloseOnExecAndNoneOutlivesTheInbox(t *testing.T) {
	before := fdCount(t)
	in, err := NewInbox(BGPD)
	if code(err) == FilesystemRefused {
		unavailable(t, "temporary directory is not on a filesystem the lease proof accepts")
	}
	if err != nil {
		t.Fatal(err)
	}
	put(t, in, stream(BGPD), streamBody)
	in.afterCopy = func() {
		entries, _ := os.ReadDir("/proc/self/fd")
		for _, e := range entries {
			fd, _ := strconv.Atoi(e.Name())
			if flags, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0); err == nil && fd > 2 && flags&unix.FD_CLOEXEC == 0 {
				t.Errorf("descriptor %d is inheritable while sealing", fd)
			}
		}
	}
	s := mustSeal(t, in)
	if flags, err := unix.FcntlInt(s.f.Fd(), unix.F_GETFD, 0); err != nil || flags&unix.FD_CLOEXEC == 0 {
		t.Fatalf("snapshot descriptor is inheritable: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if err := in.Close(); err != nil {
		t.Fatal(err)
	}
	if after := fdCount(t); after != before {
		t.Fatalf("descriptors %d before, %d after Close", before, after)
	}
	if _, err := s.ReadAt(make([]byte, 1), 0); code(err) != Closed {
		t.Fatalf("read after Close: %v", err)
	}
}

func TestCloseIsBoundedAndRetryable(t *testing.T) {
	in, err := NewInbox(BGPD)
	if code(err) == FilesystemRefused {
		unavailable(t, "temporary directory is not on a filesystem the lease proof accepts")
	}
	if err != nil {
		t.Fatal(err)
	}
	// A producer leaves a subdirectory with something in it: Close does not descend.
	sub := filepath.Join(in.Path(), "sub")
	if err := os.Mkdir(sub, 0o700); err != nil {
		t.Fatal(err)
	}
	inner := filepath.Join(sub, "x")
	if err := os.WriteFile(inner, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	put(t, in, "file", "x")
	if err := in.Close(); code(err) != CleanupIncomplete {
		t.Fatalf("Close with a nonempty subdirectory: %v", err)
	}
	if _, err := os.Stat(filepath.Join(in.Path(), "file")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("plain entries were not removed")
	}
	if _, err := in.Seal(context.Background()); code(err) != Closed {
		t.Fatalf("an inbox whose Close has begun accepts no new capture: %v", err)
	}
	if err := os.Remove(inner); err != nil {
		t.Fatal(err)
	}
	if err := in.Close(); err != nil {
		t.Fatalf("retry: %v", err)
	}
	if err := in.Close(); err != nil {
		t.Fatalf("Close is not idempotent: %v", err)
	}
	if _, err := os.Stat(in.Path()); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("directory remains")
	}
	t.Run("more entries than the bound", func(t *testing.T) {
		in := inboxFor(t, BGPD)
		for i := 0; i < 3*maxEntries; i++ {
			put(t, in, "f"+strconv.Itoa(i), "x")
		}
		// Each call does a bounded amount of work and makes progress.
		for pass := 1; pass < 3; pass++ {
			if err := in.Close(); code(err) != CleanupIncomplete {
				t.Fatalf("pass %d: %v", pass, err)
			}
			if left, _ := os.ReadDir(in.Path()); len(left) != 3*maxEntries-pass*maxEntries {
				t.Fatalf("pass %d left %d entries", pass, len(left))
			}
		}
		if err := in.Close(); err != nil {
			t.Fatalf("final pass: %v", err)
		}
	})
	t.Run("pathname replaced", func(t *testing.T) {
		in := inboxFor(t, BGPD)
		moved := in.Path() + ".moved"
		if err := os.Rename(in.Path(), moved); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(in.Path(), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := in.Close(); code(err) != CleanupIncomplete {
			t.Fatalf("Close removed a directory that is not the inbox: %v", err)
		}
		if err := os.Remove(in.Path()); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(moved, in.Path()); err != nil {
			t.Fatal(err)
		}
	})
}

// This test documents what a Snapshot does not say. A live producer keeps its
// directory descriptor until exit and may still revoke a published stream, which
// is the v1 writer's own late-event path. The Snapshot taken before is valid and
// cannot know. A later slice must prove the producers gone before it treats a
// Snapshot as complete evidence.
func TestKnownGapASnapshotCannotSeeALaterRevocation(t *testing.T) {
	in := inboxFor(t, BGPD)
	p := put(t, in, stream(BGPD), streamBody)
	s := mustSeal(t, in)
	if err := os.Rename(p, p+".partial"); err != nil {
		t.Fatal(err)
	}
	put(t, in, stream(BGPD)+".failed", "")
	if read(t, s) != streamBody || s.SHA256() != sha256.Sum256([]byte(streamBody)) {
		t.Fatal("snapshot changed")
	}
	// The source is now a refused collection, yet the Snapshot still looks fine.
	if _, err := os.Stat(p); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("source still published")
	}
}

func TestZeroValuesRefuse(t *testing.T) {
	var in *Inbox
	if _, err := in.Seal(context.Background()); code(err) != Closed || in.Path() != "" || in.Close() != nil {
		t.Fatal("nil inbox")
	}
	zero := &Inbox{}
	if _, err := zero.Seal(context.Background()); code(err) != Closed || zero.Close() != nil {
		t.Fatal("zero inbox")
	}
	var s *Snapshot
	if s.Size() != 0 || s.SHA256() != [32]byte{} || s.Close() != nil {
		t.Fatal("nil snapshot")
	}
	if _, err := s.ReadAt(make([]byte, 1), 0); code(err) != Closed {
		t.Fatal("nil snapshot read")
	}
	z := &Snapshot{}
	if _, err := z.ReadAt(make([]byte, 1), 0); code(err) != Closed || z.Close() != nil {
		t.Fatal("zero snapshot")
	}
}

func TestConcurrentSealAndCloseAreSafe(t *testing.T) {
	in := inboxFor(t, BGPD)
	put(t, in, stream(BGPD), streamBody)
	done := make(chan struct{})
	go func() { defer close(done); _ = in.Close() }()
	s, err := in.Seal(context.Background())
	if err == nil {
		defer func() { _ = s.Close() }()
		if read(t, s) != streamBody {
			t.Fatal("snapshot bytes differ")
		}
	} else if c := code(err); c != Closed && c != UnexpectedEntry && c != Modified {
		t.Fatalf("unexpected refusal %v", err)
	}
	<-done
}

func TestRefusalTextIsFixedAndBounded(t *testing.T) {
	for c, msg := range messages {
		if len(msg) > MaxDiagnosticBytes || strings.ContainsAny(msg, "%\n\x00") || !strings.HasPrefix(msg, string(c)+":") {
			t.Errorf("%s: bad diagnostic %q", c, msg)
		}
		if got := refuse(c).Error(); got != msg {
			t.Errorf("%s: %q", c, got)
		}
	}
	if msg := refuse("made up").Error(); len(msg) > MaxDiagnosticBytes {
		t.Errorf("unknown code: %q", msg)
	}
	var r *Refusal
	if !errors.As(fmt.Errorf("wrapped: %w", refuse(Closed)), &r) {
		t.Fatal("not an error value")
	}
}

func permutations(n int) [][]int {
	if n == 0 {
		return [][]int{{}}
	}
	var out [][]int
	for _, p := range permutations(n - 1) {
		for at := 0; at <= len(p); at++ {
			q := append(append(append([]int{}, p[:at]...), n-1), p[at:]...)
			out = append(out, q)
		}
	}
	return out
}

// Close must remove every entry it can in one call, whatever order the
// filesystem lists them in. A nonempty subdirectory that is met first must not
// stop the removal of the files behind it.
func TestCloseRemovesEveryRemovableEntryInAnyOrder(t *testing.T) {
	names := []string{"sub0", "sub1", "file", "fifo", "link"}
	for _, perm := range permutations(len(names)) {
		order := map[string]int{}
		for pos, idx := range perm {
			order[names[idx]] = pos
		}
		label := make([]string, len(perm))
		for pos, idx := range perm {
			label[pos] = names[idx]
		}
		in := inboxFor(t, BGPD)
		var inners []string
		for _, sub := range []string{"sub0", "sub1"} {
			if err := os.Mkdir(filepath.Join(in.Path(), sub), 0o700); err != nil {
				t.Fatal(err)
			}
			inner := filepath.Join(in.Path(), sub, "x")
			if err := os.WriteFile(inner, nil, 0o600); err != nil {
				t.Fatal(err)
			}
			inners = append(inners, inner)
		}
		put(t, in, "file", "x")
		if err := unix.Mkfifo(filepath.Join(in.Path(), "fifo"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink("/nonexistent", filepath.Join(in.Path(), "link")); err != nil {
			t.Fatal(err)
		}
		in.reorder = func(ns []string) {
			slices.SortFunc(ns, func(a, b string) int { return order[a] - order[b] })
		}
		if err := in.Close(); code(err) != CleanupIncomplete {
			t.Fatalf("order %v: Close with nonempty subdirectories: %v", label, err)
		}
		left, _ := os.ReadDir(in.Path())
		if len(left) != 2 || left[0].Name() != "sub0" || left[1].Name() != "sub1" {
			t.Fatalf("order %v: only the nonempty subdirectories may remain, got %v", label, left)
		}
		for _, inner := range inners {
			if _, err := os.Stat(inner); err != nil {
				t.Fatalf("order %v: Close descended into a subdirectory: %v", label, err)
			}
			_ = os.Remove(inner)
		}
		if err := in.Close(); err != nil {
			t.Fatalf("order %v: retry: %v", label, err)
		}
	}
}

// Once Close has begun the inbox accepts no new capture, even when the attempt
// was incomplete and the descriptor is kept for a retry. Otherwise a producer
// could add a stream between attempts and have it sealed from a directory that is
// being torn down.
func TestCloseBeginningIsTerminalForSeal(t *testing.T) {
	in := inboxFor(t, BGPD)
	sub := filepath.Join(in.Path(), "sub")
	if err := os.Mkdir(sub, 0o700); err != nil {
		t.Fatal(err)
	}
	inner := filepath.Join(sub, "x")
	if err := os.WriteFile(inner, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := in.Close(); code(err) != CleanupIncomplete {
		t.Fatalf("first Close: %v", err)
	}
	// The producer finishes its own cleanup and drops a complete, valid stream into
	// what is now an empty directory, between the two Close attempts.
	if err := os.Remove(inner); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(sub); err != nil {
		t.Fatal(err)
	}
	put(t, in, stream(BGPD), streamBody)
	s, err := in.Seal(context.Background())
	if s != nil {
		_ = s.Close()
		t.Fatal("Seal produced a snapshot after Close began")
	}
	refused(t, err, Closed)
	// The retry still finishes the teardown, and Seal keeps refusing.
	if err := in.Close(); err != nil {
		t.Fatalf("retry: %v", err)
	}
	if _, err := in.Seal(context.Background()); code(err) != Closed {
		t.Fatalf("Seal after teardown: %v", err)
	}
	if _, err := os.Stat(in.Path()); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("directory remains")
	}
}

// Close of an inbox that already produced a Snapshot leaves the Snapshot alone.
func TestCloseDoesNotAffectAnExistingSnapshot(t *testing.T) {
	in := inboxFor(t, BGPD)
	put(t, in, stream(BGPD), streamBody)
	s := mustSeal(t, in)
	if err := in.Close(); err != nil {
		t.Fatal(err)
	}
	if read(t, s) != streamBody {
		t.Fatal("snapshot changed")
	}
}

// Every error the exported methods return is a fixed Refusal, except that ReadAt
// may also return io.EOF. A failing close of the sealed bytes is no exception.
func TestSnapshotErrorsAreFixedRefusals(t *testing.T) {
	in := inboxFor(t, BGPD)
	put(t, in, stream(BGPD), streamBody)
	s := mustSeal(t, in)
	if err := s.f.Close(); err != nil { // the descriptor goes away behind the Snapshot's back
		t.Fatal(err)
	}
	_, err := s.ReadAt(make([]byte, 4), 0)
	refused(t, err, ReadFailure, "closed", "file")
	if errors.Is(err, os.ErrClosed) || errors.Is(err, io.EOF) {
		t.Fatalf("ReadAt leaked a system error: %v", err)
	}
	err = s.Close()
	refused(t, err, CloseFailure, "already", "file")
	if errors.Is(err, os.ErrClosed) {
		t.Fatalf("Close leaked a system error: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	if _, err := s.ReadAt(make([]byte, 1), 0); code(err) != Closed {
		t.Fatalf("read after Close: %v", err)
	}
	// A healthy Snapshot returns only nil or io.EOF from ReadAt.
	in2 := inboxFor(t, Zebra)
	put(t, in2, stream(Zebra), streamBody)
	s2 := mustSeal(t, in2)
	for _, off := range []int64{0, s2.Size() - 1, s2.Size(), s2.Size() + 5} {
		if _, err := s2.ReadAt(make([]byte, 8), off); err != nil && !errors.Is(err, io.EOF) {
			t.Fatalf("ReadAt(%d): %v", off, err)
		}
	}
}

// swapDuringClose arranges, with the seam placed immediately before Close removes
// the pathname, what a same-user producer can do in that window: move the original
// directory away and put an empty one at its name.
func swapDuringClose(t *testing.T) (in *Inbox, moved string) {
	t.Helper()
	in = inboxFor(t, BGPD)
	moved = in.Path() + ".moved"
	path := in.Path()
	in.beforeRmdir = func() {
		if err := os.Rename(path, moved); err != nil {
			t.Error(err)
		}
		if err := os.Mkdir(path, 0o700); err != nil {
			t.Error(err)
		}
	}
	return in, moved
}

func linked(t *testing.T, path string, in *Inbox) bool {
	t.Helper()
	var st unix.Stat_t
	if err := unix.Lstat(path, &st); err != nil {
		return false
	}
	return uint64(st.Dev) == in.dev && st.Ino == in.ino && st.Nlink > 0 //nolint:unconvert // Dev is uint32 on some architectures.
}

// Close may return nil only when the retained directory is proven unlinked. A
// producer that moves the original away and installs an empty directory at its
// name between the check and the removal must not turn the removal of the
// replacement into a success.
func TestCloseDoesNotReportSuccessForAReplacedPathname(t *testing.T) {
	in, moved := swapDuringClose(t)
	err := in.Close()
	if !linked(t, moved, in) {
		t.Fatal("setup: the original directory is not linked at the moved name")
	}
	if err == nil {
		t.Fatalf("Close returned nil while the original directory is still linked at %s", filepath.Base(moved))
	}
	refused(t, err, CleanupIncomplete)
	if in.dir == nil || in.closed {
		t.Fatal("Close released the retained descriptor without proving the removal")
	}
	if err := in.Close(); code(err) != CleanupIncomplete {
		t.Fatalf("retry while the original is still linked: %v", err)
	}
	if !linked(t, moved, in) {
		t.Fatal("a retry unlinked the original")
	}
	// Once the original is removed by anyone, the retained descriptor proves it.
	if err := os.Remove(moved); err != nil {
		t.Fatal(err)
	}
	if err := in.Close(); err != nil {
		t.Fatalf("Close after the original was removed: %v", err)
	}
	if !in.closed {
		t.Fatal("Close returned nil but the inbox is not closed")
	}
}

// KNOWN GAP. Linux removes a directory by name and not by descriptor, so no
// check before the removal can stop a same-user process from winning the window.
// Here the empty directory it installed is removed. The blast radius is an empty,
// non-symlink directory at the inbox's own name, which that user could delete
// anyway, so no capability is gained. Preventing it needs per-producer
// confinement or a different user, and when that lands this test must flip.
func TestKnownGapCloseCanRemoveADirectorySwappedIntoItsName(t *testing.T) {
	in, moved := swapDuringClose(t)
	_ = in.Close()
	if _, err := os.Lstat(in.Path()); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the gap is closed: the swapped-in directory survived (%v)", err)
	}
	_ = os.Remove(moved)
}

// A producer that removes its own emptied inbox leaves nothing for Close to
// clean up. Close proves it through the retained descriptor instead of reporting
// an incomplete cleanup forever.
func TestCloseSucceedsWhenTheOriginalWasRemovedByAnotherProcess(t *testing.T) {
	in := inboxFor(t, BGPD)
	if err := os.Remove(in.Path()); err != nil {
		t.Fatal(err)
	}
	if err := in.Close(); err != nil {
		t.Fatalf("Close of an inbox whose directory is already gone: %v", err)
	}
	if err := in.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}

func TestCloseDoesNotMistakeAReplacementForTheOriginal(t *testing.T) {
	in := inboxFor(t, BGPD)
	moved := in.Path() + ".moved"
	if err := os.Rename(in.Path(), moved); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(in.Path(), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := in.Close(); code(err) != CleanupIncomplete {
		t.Fatalf("Close with the original alive elsewhere: %v", err)
	}
	if _, err := os.Lstat(in.Path()); err != nil {
		t.Fatalf("Close removed a directory that is not the inbox: %v", err)
	}
	_ = os.Remove(in.Path())
	_ = os.Remove(moved)
	if err := in.Close(); err != nil {
		t.Fatalf("cleanup: %v", err)
	}
}
