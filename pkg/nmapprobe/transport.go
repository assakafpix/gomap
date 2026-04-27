package nmapprobe

import (
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"time"
)

// tcpConnectable returns true if a TCP handshake to target succeeds within
// the engine's timeout. Used as a quick liveness check before running the
// probe cascade so closed/filtered ports don't waste probe time.
func (e *Engine) tcpConnectable(ctx context.Context, target string) bool {
	connectTimeout := 2 * time.Second
	if connectTimeout > e.Timeout {
		connectTimeout = e.Timeout
	}
	ctx, cancel := context.WithTimeout(ctx, connectTimeout)
	defer cancel()

	conn, err := e.Dialer.DialContext(ctx, "tcp", target)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// sendProbeWithReset connects, sends the probe payload, and reads the
// response. Returns the data and a flag indicating whether the server
// actively closed the connection (EOF / RST) rather than just staying
// silent. The peer-close signal feeds the tcpwrapped heuristic.
func (e *Engine) sendProbeWithReset(ctx context.Context, target string, probe *CompiledProbe) ([]byte, bool) {
	readWait := probeWait(probe.TotalWaitMS, e.Timeout)

	ctx, cancel := context.WithTimeout(ctx, readWait+2*time.Second)
	defer cancel()

	conn, err := e.Dialer.DialContext(ctx, "tcp", target)
	if err != nil {
		return nil, false
	}
	defer conn.Close()

	if len(probe.Payload) > 0 {
		conn.SetWriteDeadline(time.Now().Add(defaultReadTimeout))
		if _, err := conn.Write(probe.Payload); err != nil {
			// Write failure usually means the peer already closed.
			return nil, isPeerClose(err)
		}
	}

	conn.SetReadDeadline(time.Now().Add(readWait))
	data, readErr := readWithErr(conn)
	peerClosed := len(data) == 0 && isPeerClose(readErr)
	return data, peerClosed
}

// probeWait returns the read deadline duration for a probe, capped at the
// engine's overall timeout. Falls back to 5 s for probes that don't
// declare a totalwaitms.
func probeWait(totalWaitMS int, hardCap time.Duration) time.Duration {
	if totalWaitMS == 0 {
		totalWaitMS = 5000
	}
	d := time.Duration(totalWaitMS) * time.Millisecond
	if d > hardCap {
		d = hardCap
	}
	return d
}

// readAll reads from the connection into an 8 KiB buffer, doing multiple
// reads to stitch together responses that arrive in several TCP segments.
// After the first chunk arrives, follow-up reads use a short 500 ms grace
// window — long enough for normally-sized responses, short enough that we
// don't block on idle connections.
func readAll(conn net.Conn) []byte {
	data, _ := readWithErr(conn)
	return data
}

// readWithErr is readAll plus the read error so callers can distinguish
// "no data, timeout" from "no data, peer closed".
func readWithErr(conn net.Conn) ([]byte, error) {
	buf := make([]byte, defaultReadSize)

	n, err := conn.Read(buf)
	if n == 0 {
		return nil, err
	}
	total := n
	for total < len(buf) {
		conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		n, err = conn.Read(buf[total:])
		total += n
		if err != nil {
			break
		}
	}
	return buf[:total], err
}

// isPeerClose returns true if the error indicates the remote peer closed
// the connection (EOF, connection reset, broken pipe). Returns false for
// timeouts or other transient errors. This is the signal we use to detect
// tcpwrapped services: they close the connection actively rather than
// going silent.
func isPeerClose(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, io.EOF) {
		return true
	}
	// Don't treat deadline timeouts as a peer close — those mean the peer
	// stayed silent, which is the opposite signal.
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "connection reset") ||
		strings.Contains(msg, "broken pipe") ||
		strings.Contains(msg, "use of closed")
}
