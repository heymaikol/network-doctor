package simulation

// The holder command protocol's failure modes. The point of every test here is
// the difference between "the director finished with us" and "we stopped being
// able to talk to the director": the first is a clean exit, and everything else
// has to come back as an error. A holder that reports success after losing the
// pipe hands the director a simulation result nothing actually ran.
//
// Everything is in-memory. No namespaces, no sockets, no sleeps.

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

// holderTestTimeout bounds every wait in this file. It is only ever reached by
// a test that is already failing, so it can be generous.
const holderTestTimeout = 5 * time.Second

// quietRecorder is a recorder that owns no file, so nothing it is asked to
// record can fail. Its failed channel is live but empty, which is what lets a
// test prove the command loop exited for the reason under test and not because
// evidence recording broke.
func quietRecorder() *evidenceRecorder {
	return &evidenceRecorder{node: "node", failed: make(chan error, 1)}
}

// errRead is the injected read failure. It deliberately does not wrap io.EOF.
var errRead = errors.New("injected holder read failure")

// scriptedReader hands back head, then fails with err. It models a pipe that
// carried some of the conversation and then broke, which is the case that used
// to be indistinguishable from the director hanging up.
type scriptedReader struct {
	head string
	err  error
	sent bool
}

func (r *scriptedReader) Read(p []byte) (int, error) {
	if !r.sent {
		r.sent = true
		if n := copy(p, r.head); n > 0 {
			return n, nil
		}
	}
	return 0, r.err
}

// blockingReader blocks until it is released, then reports the end of the
// stream. It stands in for the holder's stdin, which is idle between director
// commands and is ended by whoever owns it, never by the reader itself.
//
// entered is closed once a Read has actually begun blocking. That is the only
// way a test can tell "the protocol reader is parked inside Read" apart from
// "the protocol reader goroutine exists but has not been scheduled yet", and
// the two are not distinguishable from the goroutine dump: an unstarted
// goroutine is reported under the compiler's own wrapper for the go statement,
// not under the function it will run.
type blockingReader struct {
	release     chan struct{}
	entered     chan struct{}
	enteredOnce sync.Once
	releaseOnce sync.Once
}

// newBlockingReader registers the release as test cleanup, so a test that fails
// before it reaches its own release still ends the stream. Without that, the
// protocol reader stays parked in Read for the rest of the binary and every
// later test waits out its full timeout on the baseline reader count.
func newBlockingReader(t *testing.T) *blockingReader {
	t.Helper()
	r := &blockingReader{release: make(chan struct{}), entered: make(chan struct{})}
	t.Cleanup(r.releaseReader)
	return r
}

func (r *blockingReader) Read([]byte) (int, error) {
	r.enteredOnce.Do(func() { close(r.entered) })
	<-r.release
	return 0, io.EOF
}

// releaseReader ends the stream, standing in for its owner closing it. A test
// that wants to observe the release calls it directly; cleanup then calls it
// again and the sync.Once makes the second call a no-op.
func (r *blockingReader) releaseReader() {
	r.releaseOnce.Do(func() { close(r.release) })
}

// awaitEntered blocks until the protocol reader has reached the blocking Read.
// Only a test that is already failing reaches the timeout.
func (r *blockingReader) awaitEntered(t *testing.T) {
	t.Helper()
	select {
	case <-r.entered:
	case <-time.After(holderTestTimeout):
		t.Fatal("the protocol reader never reached its blocking Read")
	}
}

// countingWriter fails on the nth write and records how many it saw, so a test
// can prove the loop stopped on the failed reply rather than carrying on.
type countingWriter struct {
	failOn int
	writes int
	err    error
}

func (w *countingWriter) Write(p []byte) (int, error) {
	w.writes++
	if w.writes == w.failOn {
		return 0, w.err
	}
	return len(p), nil
}

// serveResult runs the command loop off the test goroutine and reports what it
// returned, so a test can assert both the value and that it returned at all.
func serveResult(ctx context.Context, r io.Reader, w io.Writer) <-chan error {
	out := make(chan error, 1)
	go func() { out <- serveHolderCommands(ctx, r, w, nil, quietRecorder()) }()
	return out
}

func awaitServe(t *testing.T, out <-chan error) error {
	t.Helper()
	select {
	case err := <-out:
		return err
	case <-time.After(holderTestTimeout):
		t.Fatal("serveHolderCommands did not return")
		return nil
	}
}

// atLimitCommand is a command of exactly n bytes that holderCommandReply
// answers without touching the network: the JSON request is over the 1024-byte
// bound holderLookupReply applies, so it is refused before any lookup happens.
// That keeps the boundary tests about the line length and nothing else.
func atLimitCommand(n int) string {
	const prefix = "lookup "
	return prefix + strings.Repeat("a", n-len(prefix))
}

const lookupRejected = "lookup-result error"

func TestHolderCommandLimitIsBigEnoughForEveryRealCommand(t *testing.T) {
	// The longest legitimate command is a lookup carrying the largest request
	// holderLookupReply accepts. If that no longer fits, the limit is wrong and
	// the protocol would start refusing valid traffic.
	if longest := len("lookup ") + 1024; holderCommandLimit <= longest {
		t.Fatalf("holderCommandLimit = %d, want more than the longest real command (%d bytes)", holderCommandLimit, longest)
	}
}

func TestServeHolderCommandsCleanEOFIsShutdown(t *testing.T) {
	in := strings.NewReader("evidence-check\n")
	var out strings.Builder
	if err := serveHolderCommands(context.Background(), in, &out, nil, quietRecorder()); err != nil {
		t.Fatalf("clean EOF returned %v, want nil", err)
	}
	if got := out.String(); got != holderEvidenceReady+"\n" {
		t.Errorf("reply = %q, want %q", got, holderEvidenceReady+"\n")
	}
}

func TestServeHolderCommandsCancellationIsShutdown(t *testing.T) {
	reader := newBlockingReader(t)
	ctx, cancel := context.WithCancel(context.Background())
	out := serveResult(ctx, reader, io.Discard)
	cancel()
	if err := awaitServe(t, out); err != nil {
		t.Fatalf("cancellation returned %v, want nil", err)
	}
}

func TestServeHolderCommandsReturnsReadFailure(t *testing.T) {
	// The line before the failure is served first, which proves the loop was
	// running normally and that the error ended it rather than a bad command.
	in := &scriptedReader{head: "evidence-check\n", err: errRead}
	var replies strings.Builder
	err := serveHolderCommands(context.Background(), in, &replies, nil, quietRecorder())
	if !errors.Is(err, errRead) {
		t.Fatalf("read failure returned %v, want %v", err, errRead)
	}
	if got := replies.String(); got != holderEvidenceReady+"\n" {
		t.Errorf("reply before the failure = %q, want %q", got, holderEvidenceReady+"\n")
	}
}

// TestServeHolderCommandsReadFailureWrappingEOFIsNotShutdown is the reason the
// terminal record uses a sentinel of this package's own. A reader is free to
// return a failure that wraps io.EOF, and a loop that asked errors.Is(err,
// io.EOF) would report that broken pipe as a finished simulation.
func TestServeHolderCommandsReadFailureWrappingEOFIsNotShutdown(t *testing.T) {
	wrapped := fmt.Errorf("holder pipe broke: %w", io.EOF)
	in := &scriptedReader{head: "evidence-check\n", err: wrapped}
	err := serveHolderCommands(context.Background(), in, io.Discard, nil, quietRecorder())
	if err == nil {
		t.Fatal("a read failure wrapping io.EOF was reported as a clean shutdown")
	}
	if !errors.Is(err, io.EOF) {
		t.Fatalf("error = %v, want the wrapped read failure", err)
	}
}

// TestServeHolderCommandsCommandSizeBoundary pins both sides of the limit. An
// off-by-one in the scanner's buffer moves exactly one of these two cases, so
// the pair fails if the buffer is sized to holderCommandLimit rather than to
// holderCommandLimit+1.
func TestServeHolderCommandsCommandSizeBoundary(t *testing.T) {
	for _, tc := range []struct {
		name      string
		size      int
		terminate string
		wantReply string
		wantErr   error
	}{
		{"exactly the limit", holderCommandLimit, "\n", lookupRejected + "\n", nil},
		{"exactly the limit, ended by EOF", holderCommandLimit, "", lookupRejected + "\n", nil},
		{"one byte under the limit", holderCommandLimit - 1, "\n", lookupRejected + "\n", nil},
		{"one byte over the limit", holderCommandLimit + 1, "\n", "", errHolderCommandTooLong},
		{"one byte over the limit, ended by EOF", holderCommandLimit + 1, "", "", errHolderCommandTooLong},
	} {
		t.Run(tc.name, func(t *testing.T) {
			command := atLimitCommand(tc.size)
			if len(command) != tc.size {
				t.Fatalf("fixture is %d bytes, want %d", len(command), tc.size)
			}
			var replies strings.Builder
			err := serveHolderCommands(context.Background(), strings.NewReader(command+tc.terminate), &replies, nil, quietRecorder())
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("error = %v, want %v", err, tc.wantErr)
			}
			if got := replies.String(); got != tc.wantReply {
				t.Errorf("replies = %q, want %q", got, tc.wantReply)
			}
		})
	}
}

// TestOverLongCommandIsNotReportedAsCleanShutdown states the rule the size
// boundary exists to enforce, separately from the boundary itself.
func TestOverLongCommandIsNotReportedAsCleanShutdown(t *testing.T) {
	huge := strings.Repeat("a", 4*holderCommandLimit) + "\n"
	err := serveHolderCommands(context.Background(), strings.NewReader(huge), io.Discard, nil, quietRecorder())
	if !errors.Is(err, errHolderCommandTooLong) {
		t.Fatalf("error = %v, want %v", err, errHolderCommandTooLong)
	}
	// bufio's own wording is an implementation detail of the scanner, not
	// something the director should ever be shown.
	if errors.Is(err, bufio.ErrTooLong) {
		t.Error("the scanner's ErrTooLong leaked out as the protocol error")
	}
}

func TestServeHolderCommandsReturnsReplyWriteFailure(t *testing.T) {
	w := &countingWriter{failOn: 2, err: io.ErrClosedPipe}
	in := strings.NewReader("evidence-check\nevidence-check\nevidence-check\n")
	err := serveHolderCommands(context.Background(), in, w, nil, quietRecorder())
	if !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("reply write failure returned %v, want %v", err, io.ErrClosedPipe)
	}
	if w.writes != 2 {
		t.Errorf("writes = %d, want 2: the loop kept answering after the pipe broke", w.writes)
	}
}

// TestReadHolderCommandsStopsOnCancellationWithNoReceiver is the send-side leak.
// Nothing ever reads from the channel, so after the first buffered line the
// reader is blocked on a send that will never be taken. Cancelling has to
// release it.
func TestReadHolderCommandsStopsOnCancellationWithNoReceiver(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	// More lines than the channel can buffer, so a send is guaranteed to block.
	in := strings.NewReader(strings.Repeat("evidence-check\n", 8))
	done := make(chan struct{})
	go func() {
		defer close(done)
		readHolderCommands(ctx, in, make(chan holderRead, 1))
	}()
	cancel()
	select {
	case <-done:
	case <-time.After(holderTestTimeout):
		t.Fatal("the protocol reader stayed blocked on a send after cancellation")
	}
}

// TestReadHolderCommandsStopsWhenTerminalSendIsUnread covers the other send:
// the terminal record itself. The stream ends immediately, so the reader has
// nothing to do but report the end, and the buffered slot is already full.
func TestReadHolderCommandsStopsWhenTerminalSendIsUnread(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	reads := make(chan holderRead, 1)
	reads <- holderRead{line: "occupying the buffer"}
	done := make(chan struct{})
	go func() {
		defer close(done)
		readHolderCommands(ctx, strings.NewReader(""), reads)
	}()
	cancel()
	select {
	case <-done:
	case <-time.After(holderTestTimeout):
		t.Fatal("the protocol reader stayed blocked sending its terminal record")
	}
}

// holderReaderCount reports how many protocol-reader goroutines are alive. It
// reads the real stacks rather than a counter of the test's own, because the
// leak this guards against is a goroutine parked on a channel send: it stops
// doing anything observable from the outside, so "it went quiet" is exactly
// what a leak looks like and cannot be the evidence.
func holderReaderCount() int {
	buf := make([]byte, 1<<20)
	for {
		n := runtime.Stack(buf, true)
		if n < len(buf) {
			return strings.Count(string(buf[:n]), "simulation.readHolderCommands")
		}
		buf = make([]byte, 2*len(buf))
	}
}

// awaitHolderReaderCount waits for the live reader count to fall back to want.
// A reader released by cancellation still has to be scheduled before it exits,
// so this polls instead of asserting once.
func awaitHolderReaderCount(t *testing.T, want int) {
	t.Helper()
	deadline := time.Now().Add(holderTestTimeout)
	for {
		got := holderReaderCount()
		if got <= want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%d protocol reader goroutine(s) still alive, want %d: the reader was left blocked", got, want)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// endlessReader never reaches the end of its input, so the reader goroutine
// reading it can only stop by being cancelled.
type endlessReader struct{ line string }

func (r endlessReader) Read(p []byte) (int, error) { return copy(p, r.line), nil }

// TestServeHolderCommandsReleasesReaderOnEarlyReturn is the leak that survives
// a fix aimed only at ctx.Done. When an evidence failure or a write error ends
// the loop, the caller's context is still live, so the reader is released only
// if serveHolderCommands cancels a context of its own. The reader is parked on
// a send to a channel with no receiver left, which is invisible except in the
// goroutine dump.
func TestServeHolderCommandsReleasesReaderOnEarlyReturn(t *testing.T) {
	for _, tc := range []struct {
		name string
		run  func(r io.Reader) error
	}{
		{"reply write failure", func(r io.Reader) error {
			return serveHolderCommands(context.Background(), r, &countingWriter{failOn: 1, err: io.ErrClosedPipe}, nil, quietRecorder())
		}},
		{"evidence recording failure", func(r io.Reader) error {
			recorder := quietRecorder()
			recorder.failed <- errors.New("evidence recording failed")
			return serveHolderCommands(context.Background(), r, io.Discard, nil, recorder)
		}},
		{"read failure", func(r io.Reader) error {
			return serveHolderCommands(context.Background(), r, io.Discard, nil, quietRecorder())
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Earlier tests can still be winding a reader down, so the baseline is
			// measured rather than assumed to be zero.
			awaitHolderReaderCount(t, 0)
			var r io.Reader = endlessReader{line: "evidence-check\n"}
			if tc.name == "read failure" {
				r = &scriptedReader{head: "evidence-check\n", err: errRead}
			}
			if err := tc.run(r); err == nil {
				t.Fatal("early return did not report an error")
			}
			awaitHolderReaderCount(t, 0)
		})
	}
}

// TestServeHolderCommandsReleasesReaderOnCancellation states the lifetime
// contract for the ordinary cancelled shutdown, with the reader parked inside
// Read rather than on a send. Cancellation cannot interrupt a Read on an
// arbitrary io.Reader, and serveHolderCommands does not own r, so the reader
// goroutine is deliberately still alive when serveHolderCommands returns. What
// is guaranteed is that nothing else holds it: the moment the owner of the
// stream releases it, the reader leaves, with no send left to block on.
//
// In production r is the holder's os.Stdin and the owner is the director, which
// closes that pipe in nodeProc.stop and kills the process if it does not go.
// Returning from serveHolderCommands means returning from RunNode, which is the
// last thing `netdoc-sim __node` does before exiting, so the reader never
// outlives the process either way.
func TestServeHolderCommandsReleasesReaderOnCancellation(t *testing.T) {
	awaitHolderReaderCount(t, 0)
	reader := newBlockingReader(t)
	ctx, cancel := context.WithCancel(context.Background())
	out := serveResult(ctx, reader, io.Discard)
	// Cancel only once the reader is provably inside Read. Cancelling before
	// that races the scheduler rather than the code under test:
	// serveHolderCommands can observe the cancellation and return while its
	// reader goroutine is still runnable and unstarted, and an unstarted
	// goroutine does not carry readHolderCommands on its stack, so the count
	// below would read 0 with the ownership contract entirely intact.
	reader.awaitEntered(t)
	cancel()
	if err := awaitServe(t, out); err != nil {
		t.Fatalf("cancellation returned %v, want nil", err)
	}
	// Deliberately not released yet. Read has begun and cannot return until
	// release is closed, so the reader goroutine is still in readHolderCommands
	// by construction: if this ever reads 0, someone has taught
	// serveHolderCommands to close a stream it does not own, and this test
	// should be rewritten rather than deleted.
	if got := holderReaderCount(); got != 1 {
		t.Fatalf("live protocol readers after cancellation = %d, want 1: the reader is blocked in Read until the stream owner releases it", got)
	}
	// The holder's stdin is owned by the director, which closes it on teardown.
	reader.releaseReader()
	awaitHolderReaderCount(t, 0)
}
