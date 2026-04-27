package nmapprobe

import (
	"bytes"
	"os"
	"testing"
)

// loadEmbeddedForTest reads nmap-service-probes from the project root for tests.
// We don't go:embed it here to avoid duplicating the file in another build.
func loadEmbeddedForTest(t *testing.T) []Probe {
	t.Helper()
	for _, path := range []string{
		"../../nmap-service-probes",
		"../../../nmap-service-probes",
		"nmap-service-probes",
	} {
		data, err := os.ReadFile(path)
		if err == nil {
			probes, err := Parse(bytes.NewReader(data))
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			return probes
		}
	}
	t.Skip("nmap-service-probes not found")
	return nil
}
