//go:build linux || darwin

package diagnostic

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"syscall"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/sys/unix"
)

func openLANEcho(link lanLink) (net.PacketConn, error) {
	// Keep a concurrent exec from inheriting the descriptor before CLOEXEC.
	syscall.ForkLock.RLock()
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, unix.IPPROTO_ICMP)
	if err == nil {
		unix.CloseOnExec(fd)
	}
	syscall.ForkLock.RUnlock()
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), "ICMP datagram") // #nosec G115 -- socket succeeded
	defer f.Close()
	if err := configureLANEcho(fd, link); err != nil {
		return nil, err
	}
	if err := unix.Bind(fd, &unix.SockaddrInet4{Addr: link.source.As4()}); err != nil {
		return nil, err
	}
	return net.FilePacketConn(f)
}

func lanEchoProbe(link lanLink) (lanProbe, error) {
	return func(ctx context.Context, dst netip.Addr) (bool, error) {
		conn, err := openLANEcho(link)
		if err != nil {
			return false, err
		}
		defer func() { _ = conn.Close() }()
		deadline, _ := ctx.Deadline()
		if err := conn.SetDeadline(deadline); err != nil {
			return false, err
		}
		stop := context.AfterFunc(ctx, func() { _ = conn.SetDeadline(time.Now()) })
		defer stop()
		if ctx.Err() != nil {
			return false, nil
		}
		var nonce [16]byte
		rand.Read(nonce[:])
		msg := icmp.Message{Type: ipv4.ICMPTypeEcho, Body: &icmp.Echo{Seq: 1, Data: nonce[:]}}
		request, err := msg.Marshal(nil)
		if err != nil {
			return false, err
		}
		if _, err := conn.WriteTo(request, &net.UDPAddr{IP: net.IP(dst.AsSlice())}); err != nil {
			return false, lanICMPSendError(err)
		}
		var packet [128]byte
		for ctx.Err() == nil {
			n, addr, err := conn.ReadFrom(packet[:])
			if err != nil {
				break
			}
			if peer, ok := addr.(*net.UDPAddr); ok && peer.AddrPort().Addr().Unmap() == dst && lanEchoReply(packet[:n], nonce[:]) {
				return true, nil
			}
		}
		return false, nil
	}, nil
}

func lanICMPSendError(err error) error {
	if errors.Is(err, syscall.EPERM) {
		return fmt.Errorf("%w: %w", errLANICMPSendDenied, err)
	}
	return nil // destination-specific send failures do not disable the sweep
}

func lanEchoReply(packet, nonce []byte) bool {
	reply, err := icmp.ParseMessage(unix.IPPROTO_ICMP, packet)
	if err != nil || reply.Type != ipv4.ICMPTypeEchoReply || reply.Code != 0 {
		return false
	}
	// Linux assigns the echo ID from the datagram socket. The payload binds
	// the reply to this request on both systems, even when IDs are rewritten.
	echo, ok := reply.Body.(*icmp.Echo)
	return ok && echo.Seq == 1 && bytes.Equal(echo.Data, nonce)
}
