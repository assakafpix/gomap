package nmapprobe

import "strings"

// tryAllMatches walks the probe's match list, then its declared fallback
// chain, then the NULL probe's matches — first hard, then soft.
//
// Per nmap documentation:
//
//	"The matchlines that are attempted are those of the responding probe,
//	plus any probes designated by a fallback directive as well as the NULL
//	probe."
//
// The NULL probe acts as an implicit fallback for every probe. Most of
// nmap's generic patterns live there (5,000+ matches) — skipping it loses
// detections for protocols that respond uniformly to many probe payloads
// (e.g. HTTP servers that return 400 Bad Request to GenericLines but whose
// fingerprint is documented under the NULL probe).
//
// Order: hard matches first (most specific), then softmatches, walking the
// chain [current probe → explicit fallbacks → NULL] for each.
func (e *Engine) tryAllMatches(probe *CompiledProbe, data []byte) *MatchResult {
	chain := e.matchChain(probe)

	// 1. Hard matches across the whole chain.
	for _, p := range chain {
		label := matchLabel(probe.Name, p.Name)
		for i := range p.Matches {
			if r := p.Matches[i].TryMatch(data, label); r != nil {
				return r
			}
		}
	}

	// 2. Softmatches across the whole chain.
	for _, p := range chain {
		label := matchLabel(probe.Name, p.Name)
		for i := range p.SoftMatches {
			if r := p.SoftMatches[i].TryMatch(data, label); r != nil {
				return r
			}
		}
	}

	return nil
}

// matchChain assembles the probe chain: the probe itself, its declared
// fallbacks, and the NULL probe (always tried last). Names are deduplicated
// so a probe never appears twice.
func (e *Engine) matchChain(probe *CompiledProbe) []*CompiledProbe {
	chain := []*CompiledProbe{probe}
	seen := map[string]bool{probe.Name: true}

	for _, fbName := range probe.Fallback {
		fbName = strings.TrimSpace(fbName)
		if seen[fbName] {
			continue
		}
		if fb := e.lookupProbe(fbName); fb != nil {
			chain = append(chain, fb)
			seen[fbName] = true
		}
	}

	if !seen["NULL"] {
		if null := e.lookupProbe("NULL"); null != nil {
			chain = append(chain, null)
		}
	}

	return chain
}

// matchLabel formats the probe label for MatchResult.ProbeName. When the
// match came from a fallback chain, the label encodes both the original
// probe and the chained one (e.g. "GenericLines→NULL").
func matchLabel(originName, currentName string) string {
	if originName == currentName {
		return originName
	}
	return originName + "→" + currentName
}

// applyMatch copies a successful match into the DetectResult, normalizing
// service names so the output is consistent regardless of which probe path
// produced the match.
//
// Two normalizations:
//
//  1. Service name like "ssl/http" — nmap uses this when a signature
//     identifies a TLS-wrapped protocol (e.g. nginx returning "The plain
//     HTTP request was sent to HTTPS port"). The TLS half is implicit in
//     the service name itself, so we know the port speaks TLS even if
//     usedTLS=false (we sent plain bytes and got back proof of TLS in the
//     response). Strip "ssl/" and set TLS=true.
//
//  2. usedTLS && service=="http" — we got an HTTP match through a TLS-
//     wrapped probe, so the protocol is HTTPS.
func applyMatch(r *DetectResult, mr *MatchResult, probeName string, usedTLS bool) {
	r.Protocol = mr.Service
	r.Product = mr.Product
	r.Version = mr.Version
	r.Info = mr.Info
	r.Hostname = mr.Hostname
	r.OS = mr.OS
	r.TLS = usedTLS

	if rest, ok := strings.CutPrefix(r.Protocol, "ssl/"); ok {
		r.Protocol = rest
		r.TLS = true
	}
	if r.TLS && r.Protocol == "http" {
		r.Protocol = "https"
	}

	for _, cpe := range mr.CPEs {
		if cpe23 := nmapCPEToCPE23(cpe); cpe23 != "" {
			r.CPEs = append(r.CPEs, cpe23)
		}
	}

	r.Probes = append(r.Probes, probeName)
}

// nmapCPEToCPE23 converts CPE 2.2 URI "cpe:/a:vendor:product:version" to
// CPE 2.3 "cpe:2.3:a:vendor:product:version:*:*:*:*:*:*:*". Strings already
// in 2.3 form are returned unchanged.
func nmapCPEToCPE23(raw string) string {
	if raw == "" {
		return ""
	}
	if strings.HasPrefix(raw, "cpe:2.3:") {
		return raw
	}
	s, ok := strings.CutPrefix(raw, "cpe:/")
	if !ok {
		s = strings.TrimPrefix(raw, "cpe:")
	}
	parts := strings.Split(s, ":")

	const cpe23Fields = 11
	out := make([]string, cpe23Fields)
	for i := range out {
		if i < len(parts) && parts[i] != "" {
			out[i] = parts[i]
		} else {
			out[i] = "*"
		}
	}
	return "cpe:2.3:" + strings.Join(out, ":")
}
