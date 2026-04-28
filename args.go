package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/assakafpix/gomap/pkg/ports"
)

// cliOptions is the parsed, validated CLI surface. Built by parseArgs.
type cliOptions struct {
	// Scan selection
	serviceVersionScan bool

	// What to scan
	positional []string
	portList   []int
	inputFile  string

	// Tuning
	intensity   int
	concurrency int
	timeout     time.Duration

	// Network
	proxyURL string

	// Output
	jsonOut bool
	silent  bool

	// True when -h or -V was handled and main() should just return.
	exitImmediately bool
}

// parseArgs parses argv (excluding the program name) into a cliOptions.
// Returns ok=false on parse error so main() can exit non-zero. It also
// handles -h and -V internally, in which case ok=true and exitImmediately
// is set.
func parseArgs(progName string, argv []string) (*cliOptions, bool) {
	fs := flag.NewFlagSet(progName, flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	var (
		// Scan techniques.
		serviceVersionScan = fs.Bool("sV", false, "Probe open ports for service/version info")
		_                  = fs.Bool("Pn", true, "Skip host discovery (always on)")

		// Port specification
		portSpec = fs.String("p", "", "Port ranges: 22,80,443 | 1-1024 | - (all)")
		topPorts = fs.Int("top-ports", 0, "Scan N most common ports (10, 100, 1000)")

		// Input
		inputFile = fs.String("iL", "", "Input file with host or host:port lines")

		// Service detection intensity. Default is 9 (max). On a short
		// target list the extra probes cost negligible time but pull in
		// rarity-8/9 patterns that nmap excludes at its default of 7.
		intensity  = fs.Int("version-intensity", 9, "Probe intensity 0-9")
		lightAlias = fs.Bool("version-light", false, "Alias for --version-intensity 2")
		fullAlias  = fs.Bool("version-all", false, "Alias for --version-intensity 9")

		// Proxy (gomap-specific)
		proxyURL = fs.String("proxy", "", "SOCKS5 proxy URL")

		// Performance
		timeout = fs.Duration("timeout", 5*time.Second, "Per-probe timeout")
		concur1 = fs.Int("max-parallelism", 50, "Concurrent probes")
		concur2 = fs.Int("c", 0, "Alias for --max-parallelism")

		// Output
		jsonOut = fs.Bool("oJ", false, "Output JSON lines")
		silent  = fs.Bool("silent", false, "Suppress banner")

		// Misc
		showVersion = fs.Bool("V", false, "Print version and exit")
		showHelp    = fs.Bool("h", false, "Show help")
	)

	fs.Usage = func() { usage(progName) }

	// Reorder argv so flags can appear anywhere, including after positional
	// args. Required because Go's stdlib flag stops parsing at the first
	// non-flag token (unlike GNU getopt).
	if err := fs.Parse(reorderArgs(argv, valueTakingFlags)); err != nil {
		return nil, false
	}

	if *showHelp {
		usage(progName)
		return &cliOptions{exitImmediately: true}, true
	}
	if *showVersion {
		fmt.Printf("gomap %s\n", version)
		return &cliOptions{exitImmediately: true}, true
	}

	// Resolve intensity aliases.
	switch {
	case *fullAlias:
		*intensity = 9
	case *lightAlias:
		*intensity = 2
	}

	// Resolve concurrency aliases (-c overrides --max-parallelism if set).
	concurrency := *concur1
	if *concur2 > 0 {
		concurrency = *concur2
	}

	// Resolve port list (-top-ports overrides -p when both given).
	var portList []int
	switch {
	case *topPorts > 0:
		portList = ports.TopN(*topPorts)
	case *portSpec != "":
		var err error
		portList, err = ports.Parse(*portSpec)
		if err != nil {
			log.Fatalf("invalid -p spec: %v", err)
		}
	}

	return &cliOptions{
		serviceVersionScan: *serviceVersionScan,
		positional:         fs.Args(),
		portList:           portList,
		inputFile:          *inputFile,
		intensity:          *intensity,
		concurrency:        concurrency,
		timeout:            *timeout,
		proxyURL:           *proxyURL,
		jsonOut:            *jsonOut,
		silent:             *silent,
	}, true
}

// valueTakingFlags lists every flag that consumes the next argv item as
// its value. Bool flags are deliberately excluded — they don't consume a
// follow-up arg in stdlib flag's grammar (use `-flag=true` to set).
//
// Keep in sync with parseArgs above: every flag declared as String, Int,
// or Duration MUST be listed here so that reorderArgs treats the next
// argv item as a value rather than a positional target.
var valueTakingFlags = map[string]bool{
	"p":                 true,
	"top-ports":         true,
	"iL":                true,
	"version-intensity": true,
	"proxy":             true,
	"timeout":           true,
	"max-parallelism":   true,
	"c":                 true,
}

// reorderArgs splits argv into two streams — flag tokens and positional
// tokens — and returns them concatenated with all flag tokens first.
//
// This lets users write "gomap target -p 80" instead of being forced into
// "gomap -p 80 target", matching nmap's getopt-style ergonomics.
//
// Anything starting with "-" is a flag token, with two exceptions:
//   - The bare "-" (stdin sentinel) is positional.
//   - The "--" terminator forces every following token to be positional,
//     so users can target hosts whose names start with a dash.
//
// For value-taking flags (per valueTakingFlags), the next token is also
// pulled into the flag stream — unless the flag already used "-flag=value"
// form, in which case the value is part of the flag token itself.
func reorderArgs(args []string, valueFlags map[string]bool) []string {
	var flagToks, positional []string
	terminated := false

	for i := 0; i < len(args); i++ {
		a := args[i]

		if terminated {
			positional = append(positional, a)
			continue
		}
		if a == "--" {
			terminated = true
			continue
		}
		if a == "-" || !strings.HasPrefix(a, "-") {
			positional = append(positional, a)
			continue
		}

		flagToks = append(flagToks, a)

		// "-flag=value" form already carries its value; nothing to consume.
		name := strings.TrimLeft(a, "-")
		if strings.ContainsRune(name, '=') {
			continue
		}
		// Pull the next argv item if this flag takes a value.
		if valueFlags[name] && i+1 < len(args) {
			flagToks = append(flagToks, args[i+1])
			i++
		}
	}

	return append(flagToks, positional...)
}

// usage prints help in nmap-style: scan types, then options, then examples.
// Always written to stderr so it doesn't pollute -oJ output to stdout.
func usage(progName string) {
	fmt.Fprint(os.Stderr, banner)
	fmt.Fprintf(os.Stderr, "Usage: %s [Scan Types] [Options] {target specification}\n\n", progName)

	for _, section := range usageSections {
		fmt.Fprintln(os.Stderr, section.title)
		for _, line := range section.lines {
			fmt.Fprintln(os.Stderr, "  "+line)
		}
		fmt.Fprintln(os.Stderr)
	}

	fmt.Fprintln(os.Stderr, "EXAMPLES:")
	for _, ex := range examples {
		fmt.Fprintf(os.Stderr, "  %s %s\n", progName, ex)
	}
}

// usageSections is the structured help body. Each section is a heading
// plus its option lines. Keeping this declarative makes adding flags
// without forgetting to update help easier.
var usageSections = []struct {
	title string
	lines []string
}{
	{"TARGET SPECIFICATION:", []string{
		"Can pass hostnames, IP addresses, host:port pairs, or read from stdin/file.",
		"Ex: scanme.nmap.org, 192.168.1.0/24, scanme.nmap.org:22",
		"-iL <inputfilename>: Input from list of hosts/networks",
		"--                  : (or no target) Read host[:port] lines from stdin",
	}},
	{"SCAN TECHNIQUES:", []string{
		"-sV                 : Probe open ports to determine service/version info",
		"                      (default: open-port scan only, like nmap)",
	}},
	{"PORT SPECIFICATION:", []string{
		"-p <port ranges>    : Scan specified ports",
		"                      Ex: -p22,80,443 | -p1-1024 | -p- (all 65535)",
		"                      T:80 forces TCP, U:53 dropped (UDP not supported)",
		"--top-ports <N>     : Scan <N> most common ports (10, 100, 1000)",
	}},
	{"SERVICE/VERSION DETECTION:", []string{
		"--version-intensity <0-9>: Set intensity (default: 9, max)",
		"--version-light          : Alias for --version-intensity 2",
		"--version-all            : Alias for --version-intensity 9",
	}},
	{"PROXY (gomap-specific):", []string{
		"--proxy <url>       : Route all probes through a SOCKS5 proxy",
		"                      Ex: socks5://user:pass@host:port",
	}},
	{"TIMING AND PERFORMANCE:", []string{
		"--timeout <duration>: Per-probe connection timeout (default: 5s)",
		"--max-parallelism <n>: Concurrent probes (default: 50). Alias: -c",
	}},
	{"OUTPUT:", []string{
		"-oJ                 : Output JSON lines to stdout",
		"--silent            : Suppress banner, only show results",
	}},
}

var examples = []string{
	"scanme.nmap.org",
	"-sV -p22,80,443 scanme.nmap.org",
	"--top-ports 100 --proxy socks5://user:pass@proxy:1080 10.0.0.1",
	"-p- --version-intensity 9 target.example.com",
	"-iL targets.txt --proxy socks5://proxy:1080",
	"-iL targets.txt --proxy socks5://proxy:1080 -oJ",
}

// banner is the ASCII logo printed at the top of -h help. Not shown during
// normal scans (we use the nmap-style "Starting gomap ..." line instead).
const banner = `
   __ _  ___  _ __ ___   __ _ _ __
  / _` + "`" + ` |/ _ \| '_ ` + "`" + ` _ \ / _` + "`" + ` | '_ \
 | (_| | (_) | | | | | | (_| | |_) |
  \__, |\___/|_| |_| |_|\__,_| .__/
   __/ |                     | |
  |___/                      |_|     v` + version + `

  SOCKS5-native service detection — nmap-compatible CLI

`
