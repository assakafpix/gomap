package nmapprobe

import (
	"strings"
	"testing"
)

// TestImplicitNULLFallback verifies that tryAllMatches walks the NULL probe's
// matches when called with a non-NULL probe.
//
// Per nmap documentation, every probe falls back to the NULL probe's matches
// implicitly. Many of nmap's most generic patterns live in the NULL section
// (the Golang net/http softmatch, for example), so without the fallback those
// patterns never fire on data captured by other probes.
func TestImplicitNULLFallback(t *testing.T) {
	probes := loadEmbeddedForTest(t)
	compiled := CompileProbes(probes)
	engine := NewEngine(compiled, nil, 5e9, 7)

	var gl *CompiledProbe
	for i := range engine.Probes {
		if engine.Probes[i].Name == "GenericLines" {
			gl = &engine.Probes[i]
			break
		}
	}
	if gl == nil {
		t.Fatal("GenericLines probe missing from compiled DB")
	}

	// The exact response a Golang net/http server returns to GenericLines.
	data := []byte("HTTP/1.1 400 Bad Request\r\nContent-Type: text/plain; charset=utf-8\r\nConnection: close\r\n\r\n400 Bad Request")

	result := engine.tryAllMatches(gl, data)
	if result == nil {
		t.Fatal("tryAllMatches returned nil — implicit NULL fallback not working")
	}
	if !strings.Contains(result.Product, "Golang") {
		t.Errorf("got product %q, want one containing 'Golang'", result.Product)
	}
	if !strings.HasSuffix(result.ProbeName, "→NULL") {
		t.Errorf("expected probe label to indicate NULL fallback, got %q", result.ProbeName)
	}
}
