package diagnostic

import (
	"context"
	"errors"
	"fmt"
	"net"
	"runtime"
	"strconv"
	"time"
)

// pmtuProbe looks for evidence of a path-MTU black hole with no root, raw
// sockets, or DF flag, by reading the one asymmetry a normal socket exposes.
//
// The TCP handshake is the small-packet control: SYN/SYN-ACK are small enough to
// cross a narrowed link, so a completed connect already proves small packets
// arrive. The evidence is what happens to a write that requires multiple
// ordinary TCP segments: the probe pushes a payload through and then asks the
// kernel how much of it the peer has acknowledged. Acknowledged bytes are the
// only proof of forward progress an ordinary socket can offer, because a
// full-size segment that is acknowledged is a full-size segment that crossed.
//
// A completed Write proves nothing. Linux treats SO_SNDBUF as an accounting
// hint, not a ceiling, and will absorb a 24 KiB write into a socket reporting
// an 8 KiB send buffer without a byte reaching the wire, which is exactly what
// a path-MTU black hole looks like from userspace. Only socketQueued separates
// the two, so a platform that cannot read its send queue cannot reach a Pass
// here at all. The send buffer survives as detail, and as the small ceiling
// that makes a blocked write mean something.
//
// There is deliberately no small-write control: a small Write returns out of the
// send buffer whether or not the bytes ever leave the machine, so it is not
// evidence of anything.
//
// Never a Fail, by design. A peer that accepts the connection and then stops
// reading stalls us the same way, so the Warn states its evidence (bytes
// written, send buffer size, and that the handshake got through) and leaves the
// reader room to judge. Only an independent protocol timeout promotes this
// evidence into a network-path verdict.
func (o *netops) pmtuProbe(port int, proto Proto) func(context.Context, map[ProbeID]ProbeResult) ProbeResult {
	return func(ctx context.Context, deps map[ProbeID]ProbeResult) ProbeResult {
		var r ProbeResult
		dep := deps[ProbeTargetTCP]
		if dep.SelectedIP == nil {
			r.Status, r.Detail = StatusSkip, "no pinned IP from Target TCP"
			return r
		}
		// The stall is the measurement, so it needs a deadline of its own inside
		// the probe budget, since a ctx cancellation would report no bytes at all.
		wait := pmtuWriteWait
		if dl, ok := ctx.Deadline(); ok {
			if left := time.Until(dl) - pmtuHeadroom; left < wait {
				wait = left
			}
		}
		if wait <= 0 {
			r.Status, r.Detail = StatusNA, "not enough of the probe budget left to measure a stall"
			return r
		}
		ip := dep.SelectedIP
		conn, err := o.dialContext(ctx, "tcp", net.JoinHostPort(ip.String(), strconv.Itoa(port)))
		if err != nil {
			// TCP connected moments ago, so a second refusal is flakiness on the
			// path, not a verdict about it.
			r.Status, r.SelectedIP = StatusNA, ip
			r.Detail = "second connection to " + ip.String() + " failed: " + err.Error()
			return r
		}
		defer conn.Close()
		r.SelectedIP = ip
		// A requested SO_SNDBUF is only a hint. Linux doubles it, and other
		// kernels may impose a much larger minimum. Read the effective value
		// back rather than treating a locally queued Write as remote delivery.
		if tc, ok := conn.(*net.TCPConn); ok {
			if err := tc.SetWriteBuffer(pmtuSendBuffer); err != nil {
				r.Status = StatusNA
				r.Detail = "cannot bound the TCP send buffer: " + err.Error()
				return r
			}
		}
		measureBuffer := o.sendBuffer
		if measureBuffer == nil {
			measureBuffer = socketSendBuffer
		}
		measureQueued := o.queued
		if measureQueued == nil {
			measureQueued = socketQueued
		}
		// One reading before the payload decides which inference the rest of the
		// probe gets to make. A platform that can account for its send queue
		// does not care how big the send buffer is; one that cannot has nothing
		// but the send buffer, and then the buffer has to be smaller than the
		// payload for a stalled write to mean anything.
		_, queueErr := measureQueued(conn)

		sendBuffer, err := measureBuffer(conn)
		if queueErr != nil {
			if err != nil || sendBuffer <= 0 {
				r.Status = StatusNA
				r.Detail = "cannot read the effective TCP send buffer; a completed write would only prove local buffering"
				return r
			}
			if sendBuffer >= pmtuPayloadSize {
				r.Status = StatusNA
				r.Detail = fmt.Sprintf("effective TCP send buffer is %s, large enough to hold the whole probe locally", kib(sendBuffer))
				return r
			}
		}
		mss := 0
		measureMSS := o.tcpMSS
		if measureMSS == nil {
			measureMSS = socketMSS
		}
		if measured, measureErr := measureMSS(conn); measureErr == nil && measured > 0 {
			mss = measured
		}
		deadline := time.Now().Add(wait)
		if err := conn.SetWriteDeadline(deadline); err != nil {
			r.Status = StatusNA
			r.Detail = "cannot bound the bulk write: " + err.Error()
			return r
		}
		n, err := conn.Write(pmtuPayload(proto))

		mtu := o.mtuFor(dep.Iface)
		blackHole := "; the TCP handshake succeeded" + mtuNote(dep.Iface, mtu, ", and %s advertises a %d-byte MTU") +
			", consistent with a path-MTU black hole"
		delivered, queueErr := awaitAcknowledged(ctx, measureQueued, conn, n, deadline)
		switch {
		case errors.Is(queueErr, context.Canceled):
			// The watch stopped because the run was cancelled, not because
			// anything was read off the socket. Cancellation is not evidence
			// about the path, so it cannot borrow a verdict from a reading
			// that never happened.
			r.Status = StatusNA
			r.Detail = "path-MTU check canceled before the peer acknowledged the payload"
		case queueErr != nil:
			// No send-queue accounting, so an accepted write is only that:
			// bytes the local kernel took. It is not evidence they left the
			// machine, and a kernel that buffers past the size it reports makes
			// a black hole look exactly like a delivery. Pass has to rest on
			// progress something actually measured, so there is no Pass to be
			// had on this side of the switch.
			switch {
			case err == nil:
				r.Status = StatusNA
				r.Detail = fmt.Sprintf("%s accepted by the local TCP stack%s, but path-MTU delivery could not be verified: %v", kib(n), mssNote(mss), queueErr)
			case n > sendBuffer:
				r.Status = StatusNA
				r.Detail = fmt.Sprintf("%s accepted by the local TCP stack%s before the write stopped (%v), but path-MTU delivery could not be verified: %v", kib(n), mssNote(mss), err, queueErr)
			case timeoutError(err):
				// A write that blocked until the deadline without ever draining
				// a buffer smaller than the payload is measured progress, and
				// it measured none: the buffer only clears on acknowledgement.
				r.Status = StatusWarn
				r.Detail = fmt.Sprintf("stalled after %s of %s without draining the measured %s TCP send buffer%s; the TCP handshake succeeded%s, consistent with a path-MTU black hole",
					kib(n), kib(pmtuPayloadSize), kib(sendBuffer), mssNote(mss), mtuNote(dep.Iface, mtu, ", and %s advertises a %d-byte MTU"))
				r.Fix = pmtuFix(runtime.GOOS)
			default:
				r.Status = StatusNA
				r.Detail = fmt.Sprintf("inconclusive; the peer dropped the connection after %s: %v", kib(n), err)
			}
		case err != nil && !timeoutError(err):
			// Ahead of the acknowledgement check on purpose: a reset purges the
			// send queue, so a dropped connection reads as a fully drained one.
			r.Status = StatusNA
			r.Detail = fmt.Sprintf("inconclusive; the peer dropped the connection after %s: %v", kib(n), err)
		case delivered > 0:
			// Acknowledgement is cumulative and TCP fills segments from the front
			// of the payload, so the peer cannot have acknowledged any of a
			// 24 KiB write without its leading full-size segment crossing. A
			// small tail that arrives out of order is only SACKed, which does
			// not move this counter.
			r.Status = StatusPass
			r.Detail = fmt.Sprintf("%s of the %s payload acknowledged by the peer%s", kib(delivered), kib(pmtuPayloadSize), mssNote(mss))
		default:
			r.Status = StatusWarn
			r.Detail = fmt.Sprintf("%s written, none of it acknowledged within %v%s%s", kib(n), wait, mssNote(mss), blackHole)
			r.Fix = pmtuFix(runtime.GOOS)
		}
		return r
	}
}

// pmtuQueueSample paces the drain watch. It is a polling interval, not a
// threshold: the answer does not depend on it, only how soon a healthy path is
// let off the deadline.
const pmtuQueueSample = 50 * time.Millisecond

// awaitAcknowledged reports how much of the payload the peer has acknowledged,
// watching the local send queue until some of it drains or the deadline passes.
//
// Sampling rather than reading once is what keeps the answer honest on a path
// with real latency: Write returns the moment the kernel accepts the bytes, so
// immediately afterwards nothing is acknowledged yet even on a healthy link.
// Once Write has returned nothing more enters the queue, so every later sample
// is monotone and the first sign of progress settles it. A black hole never
// produces one: its segments are all too big to cross, so nothing is ever
// acknowledged and the loop runs out the deadline it was already going to
// spend.
//
// The connection was dialled with ctx, but an established socket does not care
// that ctx was cancelled afterwards, so this watch is the only thing left that
// can notice. It reports the cancellation rather than a reading, since nothing
// was measured and a run being torn down is not evidence about the path.
func awaitAcknowledged(ctx context.Context, measure func(net.Conn) (int, error), conn net.Conn, written int, deadline time.Time) (int, error) {
	for {
		queued, err := measure(conn)
		if err != nil {
			return 0, err
		}
		delivered := written - queued
		if delivered > 0 || !time.Now().Before(deadline) {
			return delivered, nil
		}
		select {
		case <-ctx.Done():
			if errors.Is(ctx.Err(), context.Canceled) {
				return 0, ctx.Err()
			}
			// Out of budget rather than cancelled, which is the deadline above
			// arriving from the other direction, so it answers the same way.
			return delivered, nil
		case <-time.After(pmtuQueueSample):
		}
	}
}

func mssNote(mss int) string {
	if mss <= 0 {
		return ""
	}
	return fmt.Sprintf(" at a %d-byte TCP MSS", mss)
}

// pmtuPayload is the byte pattern the PMTU probe pushes at the target: legible
// to whoever finds it in a packet capture or a server log. It is not guaranteed
// harmless to an unknown application protocol.
func pmtuPayload(proto Proto) []byte {
	filler := []byte("netdoc path-mtu probe, discard me. ")
	out := make([]byte, 0, pmtuPayloadSize)
	if proto == ProtoTLSHTTP {
		out = append(out, tlsRecordHeader...)
	}
	for len(out) < pmtuPayloadSize {
		out = append(out, filler[:min(len(filler), pmtuPayloadSize-len(out))]...)
	}
	return out
}

// kib renders a byte count the way the numbers in this probe are chosen: in
// whole KiB, rounded down, since a partial KiB never changes the reading.
func kib(n int) string {
	return strconv.Itoa(n>>10) + " KiB"
}

// mtuNote fills format with iface and mtu, or returns nothing when the MTU
// couldn't be read, since the verdict doesn't depend on knowing the number.
func mtuNote(iface string, mtu int, format string) string {
	if mtu <= 0 {
		return ""
	}
	return fmt.Sprintf(format, iface, mtu)
}

// mtuFor reports the MTU of the named interface, or 0 when there isn't one to
// read.
func (o *netops) mtuFor(name string) int {
	if name == "" || o.interfaces == nil {
		return 0
	}
	ifaces, _ := o.interfaces()
	for _, ifi := range ifaces {
		if ifi.Name == name && ifi.MTU > 0 {
			return ifi.MTU
		}
	}
	return 0
}
