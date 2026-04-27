package nmapprobe

import (
	"context"
	"net"
	"os"
	"testing"
	"time"
)

// TestLive443 connects to scanme.sh:443 and exercises the TLS fallback path
// directly. Skipped unless GOMAP_LIVE=1 is set so CI doesn't make network calls.
func TestLive443(t *testing.T) {
	if os.Getenv("GOMAP_LIVE") != "1" {
		t.Skip("set GOMAP_LIVE=1 to run network tests")
	}

	probes := loadEmbeddedForTest(t)
	compiled := CompileProbes(probes)

	dialer := &net.Dialer{Timeout: 8 * time.Second}
	engine := NewEngine(compiled, contextDialer{dialer}, 12*time.Second, 7)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Direct test of tlsHandshakes.
	if !engine.tlsHandshakes(ctx, "scanme.sh", "scanme.sh:443") {
		t.Fatal("tlsHandshakes returned false on scanme.sh:443 — handshake failed")
	}
	t.Log("✓ TLS handshake works")

	// Direct test of tlsProbeData with GenericLines.
	probe := engine.lookupProbe("GenericLines")
	if probe == nil {
		t.Fatal("GenericLines probe missing")
	}
	data := engine.tlsProbeData(ctx, "scanme.sh", "scanme.sh:443", probe.Payload)
	if len(data) == 0 {
		t.Fatal("tlsProbeData returned no data for GenericLines on scanme.sh:443")
	}
	t.Logf("✓ TLS GenericLines got %d bytes: %.80q", len(data), string(data))

	// Run match against this real data.
	mr := engine.tryAllMatches(probe, data)
	if mr == nil {
		t.Fatal("tryAllMatches returned nil on real 443 GenericLines data")
	}
	t.Logf("matched: service=%q product=%q soft=%v probe=%q", mr.Service, mr.Product, mr.IsSoft, mr.ProbeName)

	// Now test the full tlsFallback function.
	result := engine.tlsFallback(ctx, "scanme.sh", "scanme.sh:443")
	if result == nil {
		t.Fatal("tlsFallback returned nil")
	}
	t.Logf("tlsFallback result: protocol=%q product=%q tls=%v", result.Protocol, result.Product, result.TLS)
	if result.Product == "" {
		t.Error("expected product to be populated by softmatch")
	}
}

type contextDialer struct{ d *net.Dialer }

func (c contextDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return c.d.DialContext(ctx, network, address)
}
