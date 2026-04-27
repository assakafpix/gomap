package nmapprobe

import (
	"context"
	"crypto/tls"
	"time"
)

// permissiveTLSConfig builds the tls.Config used for service detection.
//
// We deliberately allow TLS 1.0 and 1.1 (which Go's defaults rejected since
// Go 1.18). Service detection is a survey activity, not a security-critical
// data exchange — refusing to talk to a legacy TLS server means we report
// it as "tcpwrapped" while nmap correctly identifies it. We never send
// secrets and we never trust certificates (InsecureSkipVerify is on), so
// allowing weak versions has no security impact on the scanner itself.
//
// We do NOT advertise "h2" ALPN: an h2-negotiating server would treat our
// HTTP/1.x payloads as HTTP/2 framing and return binary SETTINGS frames
// that no nmap signature can match. Forcing http/1.1 keeps responses
// readable.
func permissiveTLSConfig(host string) *tls.Config {
	return &tls.Config{
		ServerName:         host,
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS10,
		NextProtos:         []string{"http/1.1"},
	}
}

// sendProbeTLS wraps a single probe in TLS for ports a probe explicitly
// lists as `sslports`. Returns the response and a usedTLS flag — even if
// the read came back empty, usedTLS=true tells the caller we successfully
// negotiated TLS so it can attribute that to the result.
func (e *Engine) sendProbeTLS(ctx context.Context, host, target string, probe *CompiledProbe) ([]byte, bool) {
	ctx, cancel := context.WithTimeout(ctx, e.Timeout)
	defer cancel()

	conn, err := e.Dialer.DialContext(ctx, "tcp", target)
	if err != nil {
		return nil, false
	}
	defer conn.Close()

	tlsConn := tls.Client(conn, permissiveTLSConfig(host))
	tlsConn.SetDeadline(time.Now().Add(defaultReadTimeout))
	if err := tlsConn.Handshake(); err != nil {
		return nil, false
	}

	if len(probe.Payload) > 0 {
		tlsConn.SetWriteDeadline(time.Now().Add(defaultReadTimeout))
		if _, err := tlsConn.Write(probe.Payload); err != nil {
			return nil, true
		}
	}

	tlsConn.SetReadDeadline(time.Now().Add(defaultReadTimeout))
	return readAll(tlsConn), true
}

// tlsFallback runs HTTP-shaped probes inside TLS to identify the service
// behind a TLS-only port. Returns nil when TLS isn't actually speakable on
// the port (so callers don't falsely label plain TCP as TLS).
//
// This mirrors what nmap does for sslports: speak HTTP through TLS so that
// HTTP softmatches (like the Golang 400 Bad Request signature) can fire.
func (e *Engine) tlsFallback(ctx context.Context, host, target string) *DetectResult {
	if !e.tlsHandshakes(ctx, host, target) {
		return nil
	}

	result := &DetectResult{TLS: true}
	probesToTry := []string{"GetRequest", "GenericLines", "HTTPOptions"}

	var firstBanner string
	var bestSoft *MatchResult

	for _, probeName := range probesToTry {
		probe := e.lookupProbe(probeName)
		if probe == nil {
			continue
		}

		data := e.tlsProbeData(ctx, host, target, probe.Payload)
		if len(data) == 0 {
			continue
		}
		if firstBanner == "" {
			firstBanner = sanitize(data, 256)
		}

		mr := e.tryAllMatches(probe, data)
		if mr == nil {
			continue
		}
		if !mr.IsSoft {
			fillTLSResult(result, mr)
			return result
		}
		if bestSoft == nil {
			bestSoft = mr
		}
	}

	if bestSoft != nil {
		fillTLSResult(result, bestSoft)
		return result
	}

	// TLS up but no HTTP-shaped match — could be a non-HTTP TLS service.
	if firstBanner != "" && genericHTTPRe.MatchString(firstBanner) {
		result.Protocol = "https"
	} else {
		result.Protocol = "tls"
	}
	return result
}

// fillTLSResult copies a MatchResult into a TLS-context DetectResult,
// promoting `http`/bare-TLS protocol names to `https` and converting CPEs
// to 2.3 form.
func fillTLSResult(r *DetectResult, mr *MatchResult) {
	r.Protocol = mr.Service
	if isBareTLS(r.Protocol) || r.Protocol == "http" {
		r.Protocol = "https"
	}
	r.Product = mr.Product
	r.Version = mr.Version
	r.Info = mr.Info
	for _, cpe := range mr.CPEs {
		if c := nmapCPEToCPE23(cpe); c != "" {
			r.CPEs = append(r.CPEs, c)
		}
	}
}

// tlsHandshakes returns true if a TLS handshake to target succeeds. This
// is the gate before any TLS-wrapped probing — without it, we'd return
// false "tls" results on plain TCP ports.
func (e *Engine) tlsHandshakes(ctx context.Context, host, target string) bool {
	ctx, cancel := context.WithTimeout(ctx, e.Timeout)
	defer cancel()

	conn, err := e.Dialer.DialContext(ctx, "tcp", target)
	if err != nil {
		return false
	}
	defer conn.Close()

	tlsConn := tls.Client(conn, permissiveTLSConfig(host))
	tlsConn.SetDeadline(time.Now().Add(defaultReadTimeout))
	return tlsConn.Handshake() == nil
}

// tlsProbeData opens a TLS connection, sends a single payload, and reads
// the response. The TLS analog of sendProbeWithReset for the fallback path.
func (e *Engine) tlsProbeData(ctx context.Context, host, target string, payload []byte) []byte {
	ctx, cancel := context.WithTimeout(ctx, e.Timeout)
	defer cancel()

	conn, err := e.Dialer.DialContext(ctx, "tcp", target)
	if err != nil {
		return nil
	}
	defer conn.Close()

	tlsConn := tls.Client(conn, permissiveTLSConfig(host))
	tlsConn.SetDeadline(time.Now().Add(defaultReadTimeout))
	if err := tlsConn.Handshake(); err != nil {
		return nil
	}

	if len(payload) > 0 {
		tlsConn.SetWriteDeadline(time.Now().Add(defaultReadTimeout))
		if _, err := tlsConn.Write(payload); err != nil {
			return nil
		}
	}
	tlsConn.SetReadDeadline(time.Now().Add(defaultReadTimeout))
	return readAll(tlsConn)
}

// isBareTLS returns true if a service name indicates TLS was detected but
// the underlying protocol is unknown — we should keep probing.
func isBareTLS(service string) bool {
	switch service {
	case "ssl", "ssl/tls", "tls":
		return true
	}
	return false
}
