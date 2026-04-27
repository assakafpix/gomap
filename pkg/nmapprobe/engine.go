// Package nmapprobe is a service-version detection engine driven by the
// nmap-service-probes file format. It exposes three layers:
//
//   - Parse / CompileProbes: load nmap's signature DB
//   - Engine.Detect: full probe cascade with version extraction
//   - Engine.DetectOpen: fast TCP-connect liveness check, no probes
//
// The engine sources every fingerprint from nmap's database (see the
// repository's NOTICE file for the upstream license). Outputs are CPE 2.3
// strings ready for vulnerability databases.
//
// Implementation notes are in the per-file comments:
//
//   - detect.go      — the probe cascade and result assembly
//   - match.go       — match dispatching, NULL probe fallback, CPE conversion
//   - transport.go   — connection management, TCP/TLS read primitives
//   - tls.go         — TLS handshake + TLS-wrapped probe sequence
//   - fingerprint.go — generic banner-shape fingerprints, last-resort path
//   - parser.go      — nmap-service-probes file parser
//   - matcher.go     — pattern compilation (regexp2 + Latin-1 byte trick)
package nmapprobe

import (
	"time"

	"golang.org/x/net/proxy"
)

const (
	maxIntensity       = 9
	defaultReadSize    = 8192
	defaultReadTimeout = 4 * time.Second
)

// Engine drives service detection using compiled nmap probes.
//
// A zero Engine is unusable; construct via NewEngine.
type Engine struct {
	Probes    []CompiledProbe
	Dialer    proxy.ContextDialer
	Timeout   time.Duration
	Intensity int // 0-9: which rarity probes to include

	// probeIndex maps probe name to index in Probes for fallback resolution.
	probeIndex map[string]int
}

// NewEngine creates an engine from compiled probes.
//
// intensity is clamped to [0, 9] to match nmap's --version-intensity range.
// Pass nil probes when only DetectOpen will be called (fast mode).
func NewEngine(probes []CompiledProbe, dialer proxy.ContextDialer, timeout time.Duration, intensity int) *Engine {
	if intensity < 0 {
		intensity = 0
	}
	if intensity > maxIntensity {
		intensity = maxIntensity
	}

	idx := make(map[string]int, len(probes))
	for i, p := range probes {
		idx[p.Name] = i
	}

	return &Engine{
		Probes:     probes,
		Dialer:     dialer,
		Timeout:    timeout,
		Intensity:  intensity,
		probeIndex: idx,
	}
}

// DetectResult holds the final detection for a single host:port.
//
// Open is true iff the TCP handshake succeeded. If Open is false, every
// other field is zero-valued.
type DetectResult struct {
	Host     string   `json:"host"`
	Port     int      `json:"port"`
	Open     bool     `json:"open"`
	Protocol string   `json:"protocol"`
	TLS      bool     `json:"tls"`
	Product  string   `json:"product,omitempty"`
	Version  string   `json:"version,omitempty"`
	Info     string   `json:"info,omitempty"`
	Hostname string   `json:"hostname,omitempty"`
	OS       string   `json:"os,omitempty"`
	CPEs     []string `json:"cpes,omitempty"`
	Banner   string   `json:"banner,omitempty"`
	Probes   []string `json:"probes,omitempty"`
}

// lookupProbe returns the compiled probe by name, or nil if not loaded.
func (e *Engine) lookupProbe(name string) *CompiledProbe {
	idx, ok := e.probeIndex[name]
	if !ok {
		return nil
	}
	return &e.Probes[idx]
}
