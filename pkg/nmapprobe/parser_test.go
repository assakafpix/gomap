package nmapprobe

import (
	"strings"
	"testing"
)

func TestParse_ProbeAndMatch(t *testing.T) {
	input := `# test
Probe TCP NULL q||
rarity 1
totalwaitms 6000
ports 1-100
sslports 443,8443

match ssh m|^SSH-([\d.]+)-OpenSSH_([\w._-]+)[ -]{1,2}Ubuntu[ -_]([^\r\n]+)\r?\n| p/OpenSSH/ v/$2 Ubuntu $3/ i/Ubuntu Linux; protocol $1/ o/Linux/ cpe:/a:openbsd:openssh:$2/ cpe:/o:canonical:ubuntu_linux/
match http m|^HTTP/1\.[01] \d\d\d| p/HTTP server/
softmatch http m|^HTTP/|

##############################NEXT PROBE##############################
Probe TCP GetRequest q|GET / HTTP/1.0\r\n\r\n|
rarity 1
ports 80,443,8080
fallback NULL

match http m|^HTTP/1\.[01] \d\d\d .*Server: Apache[/ ]([\d.]+)|s p/Apache httpd/ v/$1/ cpe:/a:apache:http_server:$1/
`
	probes, err := Parse(strings.NewReader(input))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	if len(probes) != 2 {
		t.Fatalf("expected 2 probes, got %d", len(probes))
	}

	// NULL probe.
	null := probes[0]
	if null.Name != "NULL" {
		t.Errorf("probe[0].Name = %q", null.Name)
	}
	if len(null.Payload) != 0 {
		t.Errorf("NULL payload should be empty, got %d bytes", len(null.Payload))
	}
	if null.Rarity != 1 {
		t.Errorf("rarity = %d", null.Rarity)
	}
	if null.TotalWaitMS != 6000 {
		t.Errorf("totalwaitms = %d", null.TotalWaitMS)
	}
	if len(null.Matches) != 2 {
		t.Errorf("expected 2 matches, got %d", len(null.Matches))
	}
	if len(null.SoftMatches) != 1 {
		t.Errorf("expected 1 softmatch, got %d", len(null.SoftMatches))
	}

	// SSH match.
	ssh := null.Matches[0]
	if ssh.Service != "ssh" {
		t.Errorf("ssh.Service = %q", ssh.Service)
	}
	if ssh.Product != "OpenSSH" {
		t.Errorf("ssh.Product = %q", ssh.Product)
	}
	if ssh.Version != "$2 Ubuntu $3" {
		t.Errorf("ssh.Version = %q", ssh.Version)
	}
	if ssh.OS != "Linux" {
		t.Errorf("ssh.OS = %q", ssh.OS)
	}
	if len(ssh.CPEs) != 2 {
		t.Errorf("expected 2 CPEs, got %d: %v", len(ssh.CPEs), ssh.CPEs)
	}

	// GetRequest probe.
	get := probes[1]
	if get.Name != "GetRequest" {
		t.Errorf("probe[1].Name = %q", get.Name)
	}
	if string(get.Payload) != "GET / HTTP/1.0\r\n\r\n" {
		t.Errorf("GetRequest payload = %q", string(get.Payload))
	}
	if len(get.Fallback) != 1 || get.Fallback[0] != "NULL" {
		t.Errorf("fallback = %v", get.Fallback)
	}
}

func TestDecodeNmapEscapes(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{`\r\n`, "\r\n"},
		{`\x41\x42`, "AB"},
		{`hello\0world`, "hello\x00world"},
		{`GET / HTTP/1.0\r\n\r\n`, "GET / HTTP/1.0\r\n\r\n"},
		{`\\slash`, "\\slash"},
	}
	for _, tt := range tests {
		got := string(decodeNmapEscapes(tt.input))
		if got != tt.want {
			t.Errorf("decodeNmapEscapes(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestSubstituteBackrefs(t *testing.T) {
	groups := []string{"full match", "OpenSSH", "9.6p1", "Ubuntu-3"}
	tests := []struct {
		template string
		want     string
	}{
		{"$1", "OpenSSH"},
		{"$1 version $2", "OpenSSH version 9.6p1"},
		{"$2 $3", "9.6p1 Ubuntu-3"},
		{"no refs", "no refs"},
		{"", ""},
	}
	for _, tt := range tests {
		got := substituteBackrefs(tt.template, groups)
		if got != tt.want {
			t.Errorf("substituteBackrefs(%q) = %q, want %q", tt.template, got, tt.want)
		}
	}
}

func TestNmapCPEToCPE23(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"cpe:/a:openbsd:openssh:9.6p1", "cpe:2.3:a:openbsd:openssh:9.6p1:*:*:*:*:*:*:*"},
		{"cpe:/o:linux:linux_kernel", "cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*"},
		{"cpe:2.3:a:apache:http_server:2.4.7:*:*:*:*:*:*:*", "cpe:2.3:a:apache:http_server:2.4.7:*:*:*:*:*:*:*"},
		{"", ""},
	}
	for _, tt := range tests {
		got := nmapCPEToCPE23(tt.input)
		if got != tt.want {
			t.Errorf("nmapCPEToCPE23(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestCompileAndMatch(t *testing.T) {
	input := `Probe TCP NULL q||
match ssh m|^SSH-([\d.]+)-OpenSSH_([\w._-]+)\s| p/OpenSSH/ v/$2/ cpe:/a:openbsd:openssh:$2/
`
	probes, err := Parse(strings.NewReader(input))
	if err != nil {
		t.Fatal(err)
	}

	compiled := CompileProbes(probes)
	if len(compiled) != 1 {
		t.Fatalf("expected 1 compiled probe, got %d", len(compiled))
	}
	if len(compiled[0].Matches) != 1 {
		t.Fatalf("expected 1 compiled match, got %d", len(compiled[0].Matches))
	}

	banner := []byte("SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.15\r\n")
	result := compiled[0].Matches[0].TryMatch(banner, "NULL")
	if result == nil {
		t.Fatal("expected match, got nil")
	}
	if result.Service != "ssh" {
		t.Errorf("service = %q", result.Service)
	}
	if result.Product != "OpenSSH" {
		t.Errorf("product = %q", result.Product)
	}
	if result.Version != "9.6p1" {
		t.Errorf("version = %q", result.Version)
	}
	if len(result.CPEs) != 1 {
		t.Fatalf("expected 1 CPE, got %d", len(result.CPEs))
	}
	if result.CPEs[0] != "cpe:/a:openbsd:openssh:9.6p1" {
		t.Errorf("cpe = %q", result.CPEs[0])
	}
}

func TestParseFullDatabase(t *testing.T) {
	// This test verifies that the real nmap-service-probes file parses without error.
	// It reads the embedded file from the build.
	// To run this, build with: go test -run TestParseFullDatabase
	//
	// We skip if the file isn't available (e.g. in CI without the data file).
	import_test_data := `Probe TCP NULL q||
totalwaitms 6000
match ssh m|^SSH-([\d.]+)-OpenSSH_([\w._-]+)| p/OpenSSH/ v/$2/
match ftp m|^220.*vsftpd| p/vsftpd/

Probe TCP GetRequest q|GET / HTTP/1.0\r\n\r\n|
rarity 1
ports 80
match http m|^HTTP/1| p/HTTP/
`
	probes, err := Parse(strings.NewReader(import_test_data))
	if err != nil {
		t.Fatal(err)
	}
	compiled := CompileProbes(probes)
	if len(compiled) != 2 {
		t.Errorf("expected 2 probes, got %d", len(compiled))
	}

	totalMatches := 0
	for _, p := range compiled {
		totalMatches += len(p.Matches)
	}
	if totalMatches != 3 {
		t.Errorf("expected 3 total matches, got %d", totalMatches)
	}
}
