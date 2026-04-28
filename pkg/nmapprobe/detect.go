package nmapprobe

import (
	"context"
	"fmt"
	"slices"
)

// DetectOpen is the fast path: just check whether the port accepts a TCP
// connection. No probes, no banner reading, no fingerprint matching.
//
// The returned DetectResult has Open set if the handshake succeeded; the
// caller is expected to fill in Protocol from a port-name lookup if desired.
// Mirrors what nmap reports without -sV.
func (e *Engine) DetectOpen(ctx context.Context, host string, port int) DetectResult {
	result := DetectResult{Host: host, Port: port}
	target := fmt.Sprintf("%s:%d", host, port)
	if e.tcpConnectable(ctx, target) {
		result.Open = true
	}
	return result
}

// Detect runs full service-version detection against host:port.
//
// The cascade has six stages, each is tried in order until one resolves:
//
//  1. TCP liveness — if we can't connect, return early (Open = false).
//  2. Probe loop — send probes by priority. A hard match returns immediately
//     (unless it's a bare "ssl" match, which means TLS is up but the
//     underlying service is unknown — we break to stage 4).
//  3. Soft match — if any probe scored a softmatch, apply it.
//  4. TLS fallback — wrap HTTP-shaped probes in TLS to identify HTTPS.
//  5. tcpwrapped heuristic — when every probe got 0 bytes and at least one
//     saw the peer actively close, we report tcpwrapped (matches nmap).
//  6. Generic banner fingerprint — last-resort wire-shape recognition for
//     when no nmap pattern matched but we did capture data.
func (e *Engine) Detect(ctx context.Context, host string, port int) DetectResult {
	result := DetectResult{Host: host, Port: port}
	target := fmt.Sprintf("%s:%d", host, port)

	if !e.tcpConnectable(ctx, target) {
		return result
	}
	result.Open = true

	loop := e.runProbeLoop(ctx, host, port, target, &result)

	// Apply softmatch first if we found one — it's actual evidence from a
	// probe response, so it beats the TLS fallback.
	if loop.softMatch != nil {
		applyMatch(&result, loop.softMatch, loop.softMatch.ProbeName, false)
		return result
	}

	// TLS fallback: reach for it when no probe identified the service or
	// we only saw the bare "ssl" / "ssl/tls" service. tlsFallback returns
	// nil for plain TCP ports so we never falsely label them as TLS.
	if result.Protocol == "" || isBareTLS(result.Protocol) {
		if tlsResult := e.tlsFallback(ctx, host, target); tlsResult != nil {
			mergeTLSResult(&result, tlsResult)
			return result
		}
	}

	// tcpwrapped detection.
	if result.Protocol == "" && loop.isTCPWrapped() {
		result.Protocol = "tcpwrapped"
		result.Info = "service behind TCP wrapper or filtering"
		result.Probes = append(result.Probes, "tcpwrapped-heuristic")
		return result
	}

	// Generic banner fingerprint.
	if result.Protocol == "" && result.Banner != "" {
		if proto, info := genericFingerprint(result.Banner); proto != "" {
			result.Protocol = proto
			if info != "" && result.Info == "" {
				result.Info = info
			}
			result.Probes = append(result.Probes, "generic-banner")
		}
	}

	return result
}

// loopOutcome aggregates the bookkeeping the probe loop needs to feed into
// downstream fallback decisions (soft match, tcpwrapped detection).
type loopOutcome struct {
	softMatch           *MatchResult
	probesAttempted     int
	emptyResponses      int
	peerClosedResponses int
}

// isTCPWrapped is the nmap "tcpwrapped" heuristic: every probe got 0 bytes,
// AND the peer actively closed at least one of those connections (EOF/RST)
// rather than just staying silent.
func (l *loopOutcome) isTCPWrapped() bool {
	return l.probesAttempted > 0 &&
		l.emptyResponses == l.probesAttempted &&
		l.peerClosedResponses > 0
}

// runProbeLoop sends probes in priority order against an open TCP port,
// updating result as it goes (banner, hard-match identification). It returns
// a loopOutcome capturing softmatch and emptiness stats for the caller's
// fallback logic.
//
// The loop stops early in two cases:
//   - A non-bareTLS hard match fires → caller short-circuits via result.Protocol
//   - A bareTLS hard match fires → result.TLS = true, break so caller uses TLS fallback
func (e *Engine) runProbeLoop(
	ctx context.Context,
	host string,
	port int,
	target string,
	result *DetectResult,
) loopOutcome {
	// Skip remaining probes only after this many SILENT empties (timeouts,
	// not peer-closes). Peer-closes are cheap (~1 ms each) and don't waste
	// scan time, so counting them toward the skip threshold needlessly
	// short-circuits services that close on garbage probes but respond to
	// the right one (e.g. modern Postgres rejects \r\n\r\n with RST but
	// returns a diagnostic ERROR packet to SMBProgNeg's malformed payload).
	const maxSilentBeforeSkip = 3

	var out loopOutcome

	for _, probeIdx := range e.probeOrder(port) {
		if ctx.Err() != nil {
			return out
		}

		probe := &e.Probes[probeIdx]
		if probe.Protocol == "UDP" {
			continue
		}

		// Skip remaining non-NULL probes if too many silent timeouts seen.
		// Each silent probe burns its full read deadline (typically several
		// seconds), so this saves real time on ports that genuinely don't
		// respond to anything. Peer-closes don't contribute to the count.
		silentEmpties := out.emptyResponses - out.peerClosedResponses
		if silentEmpties >= maxSilentBeforeSkip && probe.Name != "NULL" {
			continue
		}

		isSSLPort := slices.Contains(probe.SSLPorts, port)

		var data []byte
		var usedTLS, peerClosed bool

		out.probesAttempted++
		if isSSLPort {
			data, usedTLS = e.sendProbeTLS(ctx, host, target, probe)
		}
		if data == nil {
			data, peerClosed = e.sendProbeWithReset(ctx, target, probe)
			usedTLS = false
		}

		if len(data) == 0 {
			out.emptyResponses++
			if peerClosed {
				out.peerClosedResponses++
			}
			continue
		}
		out.emptyResponses = 0
		out.peerClosedResponses = 0

		if result.Banner == "" {
			result.Banner = sanitize(data, 256)
		}

		mr := e.tryAllMatches(probe, data)

		if mr != nil && !mr.IsSoft {
			applyMatch(result, mr, probe.Name, usedTLS)
			if !isBareTLS(mr.Service) {
				return out
			}
			// Bare TLS: stop sending plain-TCP probes (they'd just hit
			// the TLS layer and return garbage) — the caller will run
			// the TLS fallback to identify the underlying service.
			result.TLS = true
			return out
		}

		if mr != nil && mr.IsSoft && out.softMatch == nil {
			out.softMatch = mr
			out.softMatch.ProbeName = probe.Name
		}
	}

	return out
}

// probeOrder returns the indices of probes to try for this port, ordered:
//  1. NULL probe first (always — its matches are nmap's most generic).
//  2. Probes whose `ports`/`sslports` directive includes this port.
//  3. All other probes within the configured intensity threshold.
//
// Per-port targeted probes bypass the rarity/intensity gate. nmap's
// documented behavior is that a probe's `ports` directive is an
// explicit "if you see this port, run me" signal — the probe author
// has already decided this probe is relevant for that port. Without
// the bypass, niche services on their well-known ports get missed at
// default intensity (e.g. Redis on 6379, whose `redis-server` probe
// is rarity 8).
func (e *Engine) probeOrder(port int) []int {
	var order []int
	seen := make(map[int]bool)

	if idx, ok := e.probeIndex["NULL"]; ok {
		order = append(order, idx)
		seen[idx] = true
	}

	// Targeted probes — run regardless of rarity.
	for i, p := range e.Probes {
		if seen[i] {
			continue
		}
		if slices.Contains(p.Ports, port) || slices.Contains(p.SSLPorts, port) {
			order = append(order, i)
			seen[i] = true
		}
	}

	// Untargeted probes — gated by intensity.
	for i, p := range e.Probes {
		if seen[i] || p.Rarity > e.Intensity {
			continue
		}
		order = append(order, i)
		seen[i] = true
	}

	return order
}

// mergeTLSResult copies the non-empty fields from a TLS-fallback result
// into the main result, while preserving anything already populated by
// the probe loop (e.g. a soft hint we want to enrich).
func mergeTLSResult(dst, src *DetectResult) {
	dst.TLS = true
	if src.Product != "" {
		dst.Product = src.Product
	}
	if src.Version != "" {
		dst.Version = src.Version
	}
	if src.Protocol != "" {
		dst.Protocol = src.Protocol
	}
	if len(src.CPEs) > 0 {
		dst.CPEs = src.CPEs
	}
	dst.Probes = append(dst.Probes, "tls-fallback")
}
