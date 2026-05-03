package nmapprobe

import (
	"bytes"
	"fmt"
	"sync"
	"time"

	_ "embed"

	"golang.org/x/net/proxy"
)

// embeddedProbes is the nmap-service-probes file shipped with gomap.
// We embed it inside the library package (not main) so that any importer —
// including third-party consumers using gomap as a Go library — gets the
// probe database without needing their own copy of the file.
//
//go:embed nmap-service-probes
var embeddedProbes []byte

// EmbeddedProbes returns the raw bytes of the nmap-service-probes file
// that ships with this version of gomap. Most consumers should prefer
// DefaultEngine, which parses and caches these probes for them.
func EmbeddedProbes() []byte {
	out := make([]byte, len(embeddedProbes))
	copy(out, embeddedProbes)
	return out
}

var (
	defaultProbesOnce sync.Once
	defaultProbes     []CompiledProbe
	defaultProbesErr  error
)

// DefaultProbes returns the compiled probes from the embedded nmap-service-
// probes file. The result is cached after the first call (parsing 12k
// regexes costs ~700 ms), so subsequent calls are cheap.
//
// Library consumers wanting only a subset of probes, or a different probe
// database, should call Parse + CompileProbes directly instead.
func DefaultProbes() ([]CompiledProbe, error) {
	defaultProbesOnce.Do(func() {
		raw, err := Parse(bytes.NewReader(embeddedProbes))
		if err != nil {
			defaultProbesErr = fmt.Errorf("parse embedded probes: %w", err)
			return
		}
		defaultProbes = CompileProbes(raw)
	})
	return defaultProbes, defaultProbesErr
}

// DefaultEngine builds a service-detection Engine wired with the supplied
// dialer, using the embedded nmap probe database. The expensive parse +
// regex compilation is amortized via DefaultProbes — the first call pays
// ~700 ms, every subsequent call is essentially free.
//
// This is the recommended entry point for library consumers. Pass nil for
// dialer to build a direct (no-proxy) engine, or use
// github.com/assakafpix/gomap/pkg/dialer.New for a SOCKS5-aware dialer.
//
// intensity is clamped to [0, 9] to mirror nmap's --version-intensity.
// Pass 9 for the broadest detection, 7 for nmap's default, 2 for a quick
// scan that only sends the most common probes.
func DefaultEngine(dialer proxy.ContextDialer, timeout time.Duration, intensity int) (*Engine, error) {
	probes, err := DefaultProbes()
	if err != nil {
		return nil, err
	}
	return NewEngine(probes, dialer, timeout, intensity), nil
}
