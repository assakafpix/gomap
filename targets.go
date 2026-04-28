package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
)

// target is one host:port pair the engine will probe.
type target struct {
	host string
	port int
}

// collectTargets resolves the cliOptions's positional/file/stdin sources
// into a flat list of target structs.
//
// Precedence:
//  1. Positional args (cross-joined with the port list, or used directly
//     if they're already in host:port form).
//  2. -iL <file>: appended after positionals.
//  3. Stdin (host[:port] lines): only consulted when neither of the above
//     produced any targets, so explicit args always win over a piped tty.
func collectTargets(opts *cliOptions) ([]target, error) {
	targets, err := buildTargets(opts.positional, opts.portList, opts.inputFile)
	if err != nil {
		return nil, err
	}
	if len(targets) > 0 {
		return targets, nil
	}
	return readFromStdin()
}

// buildTargets composes the target list from positional hosts (cross-joined
// with portList) plus -iL input file. Positional args may be:
//   - bare host: "scanme.nmap.org" → expanded with portList
//   - host:port: "10.0.0.1:8443"   → used as-is, ignores portList
func buildTargets(positional []string, portList []int, inputFile string) ([]target, error) {
	var targets []target

	for _, p := range positional {
		// host:port form — accept both literal and IPv6 bracketed.
		if h, ps, err := net.SplitHostPort(p); err == nil {
			port, err := strconv.Atoi(ps)
			if err != nil {
				return nil, fmt.Errorf("invalid port in %q: %w", p, err)
			}
			targets = append(targets, target{host: h, port: port})
			continue
		}
		// Bare host — needs a port list.
		if len(portList) == 0 {
			return nil, fmt.Errorf("target %q has no port: pass -p / --top-ports, or use host:port form", p)
		}
		for _, port := range portList {
			targets = append(targets, target{host: p, port: port})
		}
	}

	if inputFile != "" {
		f, err := os.Open(inputFile)
		if err != nil {
			return nil, fmt.Errorf("open -iL file: %w", err)
		}
		defer f.Close()
		fileTargets, err := parseHostPortLines(bufio.NewScanner(f), portList)
		if err != nil {
			return nil, err
		}
		targets = append(targets, fileTargets...)
	}

	return targets, nil
}

// readFromStdin parses host[:port] lines from stdin. Returns nil
// when stdin is a terminal (so an interactive `gomap` invocation doesn't
// block waiting for piped input that isn't coming).
func readFromStdin() ([]target, error) {
	stat, _ := os.Stdin.Stat()
	if (stat.Mode() & os.ModeCharDevice) != 0 {
		return nil, nil
	}
	return parseHostPortLines(bufio.NewScanner(os.Stdin), nil)
}

// parseHostPortLines reads "host:port" or bare "host" lines. When a line
// is just a host AND a portList is provided, the host is expanded across
// every port. Comments (#) and blank lines are skipped.
func parseHostPortLines(s *bufio.Scanner, portList []int) ([]target, error) {
	var targets []target
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		if h, ps, err := net.SplitHostPort(line); err == nil {
			port, err := strconv.Atoi(ps)
			if err != nil {
				continue
			}
			targets = append(targets, target{host: h, port: port})
			continue
		}

		// Bare host — only useful if we have a port list.
		if len(portList) == 0 {
			continue
		}
		for _, port := range portList {
			targets = append(targets, target{host: line, port: port})
		}
	}
	return targets, s.Err()
}
