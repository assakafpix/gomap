package nmapprobe

import (
	"bytes"
	"testing"
)

// loadEmbeddedForTest parses the nmap-service-probes file embedded in this
// package. Tests use it to exercise the engine against the real probe DB
// without each test having to re-parse it themselves.
func loadEmbeddedForTest(t *testing.T) []Probe {
	t.Helper()
	probes, err := Parse(bytes.NewReader(embeddedProbes))
	if err != nil {
		t.Fatalf("parse embedded probes: %v", err)
	}
	return probes
}
