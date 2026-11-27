package sshverify

import (
	"net"
	"sync"
)

// bufferedConn queues writes and delivers them in order from a goroutine.
// net.Pipe is unbuffered, and both SSH peers write their identification
// string before they read; over an unbuffered pipe that is a deadlock. A TCP
// socket buffers the write, so the in-memory test transport must too.
type bufferedConn struct {
	net.Conn
	queue chan []byte
	done  chan struct{}
	once  sync.Once
}

func newBufferedConn(c net.Conn) *bufferedConn {
	b := &bufferedConn{Conn: c, queue: make(chan []byte, 256), done: make(chan struct{})}
	go func() {
		for {
			select {
			case p := <-b.queue:
				if _, err := b.Conn.Write(p); err != nil {
					return
				}
			case <-b.done:
				return
			}
		}
	}()
	return b
}

func (b *bufferedConn) Write(p []byte) (int, error) {
	cp := append([]byte(nil), p...)
	select {
	case b.queue <- cp:
		return len(p), nil
	case <-b.done:
		return 0, net.ErrClosed
	}
}

func (b *bufferedConn) Close() error {
	b.once.Do(func() { close(b.done) })
	return b.Conn.Close()
}

// bufferedPipe returns both ends of an in-memory connection, buffered so that
// simultaneous writes cannot deadlock.
func bufferedPipe() (net.Conn, net.Conn) {
	a, b := net.Pipe()
	return newBufferedConn(a), newBufferedConn(b)
}

// RemoteAddr reports a loopback TCP address. knownhosts also matches the
// remote address, and a net.Pipe address ("pipe") carries no port to match.
func (b *bufferedConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: testPort}
}
