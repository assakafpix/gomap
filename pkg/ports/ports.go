// Package ports parses nmap-style port specifications and provides
// top-N port lists derived from nmap's nmap-services frequency database.
package ports

import (
	"fmt"
	"strconv"
	"strings"
)

// Parse interprets an nmap-style port spec into a sorted, deduplicated list.
// Supported syntax:
//
//	"-"           → all ports 1-65535
//	"80"          → single port
//	"22,80,443"   → multiple ports
//	"1-1024"      → range
//	"22,80-90,443" → mixed
//	"U:53,T:80"   → protocol prefix (T: kept; U: ignored — UDP not supported)
func Parse(spec string) ([]int, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return nil, fmt.Errorf("empty port spec")
	}
	if spec == "-" {
		return rangePorts(1, 65535), nil
	}

	seen := make(map[int]bool, 64)
	var out []int

	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		// Strip protocol prefix (T: for TCP, U: for UDP, S: for SCTP).
		// We only support TCP, so silently drop U:/S: entries.
		if len(part) >= 2 && part[1] == ':' {
			switch part[0] {
			case 'T', 't':
				part = part[2:]
			case 'U', 'u', 'S', 's':
				continue
			}
		}

		if part == "-" {
			for _, p := range rangePorts(1, 65535) {
				if !seen[p] {
					seen[p] = true
					out = append(out, p)
				}
			}
			continue
		}

		if strings.Contains(part, "-") {
			start, end, err := parseRange(part)
			if err != nil {
				return nil, fmt.Errorf("invalid range %q: %w", part, err)
			}
			for p := start; p <= end; p++ {
				if !seen[p] {
					seen[p] = true
					out = append(out, p)
				}
			}
			continue
		}

		p, err := strconv.Atoi(part)
		if err != nil {
			return nil, fmt.Errorf("invalid port %q: %w", part, err)
		}
		if p < 1 || p > 65535 {
			return nil, fmt.Errorf("port %d out of range 1-65535", p)
		}
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}

	if len(out) == 0 {
		return nil, fmt.Errorf("no ports parsed from %q", spec)
	}
	return out, nil
}

// ServiceName returns the IANA-ish service name for a TCP port, derived from
// nmap's nmap-services file. Returns "" for ports without a registered name.
//
// This is the same name lookup nmap uses when invoked without -sV: a quick
// well-known port → service hint, with no probing involved. It's a hint, not
// a guarantee — the actual service on the port can be anything.
func ServiceName(port int) string {
	return portServiceNames[port]
}

// TopN returns the top N ports by frequency from nmap's nmap-services file.
// Supported sizes: 10, 100, 1000. Other values clamp to the nearest list and
// truncate to N entries.
func TopN(n int) []int {
	if n <= 0 {
		return nil
	}
	switch {
	case n <= 10:
		return top10Ports[:n]
	case n <= 100:
		return top100Ports[:n]
	case n <= 1000:
		return top1000Ports[:n]
	default:
		return top1000Ports
	}
}

func parseRange(s string) (int, int, error) {
	// Handle open-ended ranges: "-1024" → 1-1024, "1024-" → 1024-65535
	parts := strings.SplitN(s, "-", 2)
	if len(parts) != 2 {
		return 0, 0, fmt.Errorf("expected start-end")
	}

	startStr := strings.TrimSpace(parts[0])
	endStr := strings.TrimSpace(parts[1])

	start := 1
	end := 65535
	var err error

	if startStr != "" {
		start, err = strconv.Atoi(startStr)
		if err != nil {
			return 0, 0, err
		}
	}
	if endStr != "" {
		end, err = strconv.Atoi(endStr)
		if err != nil {
			return 0, 0, err
		}
	}
	if start < 1 || end > 65535 || start > end {
		return 0, 0, fmt.Errorf("invalid range %d-%d", start, end)
	}
	return start, end, nil
}

func rangePorts(start, end int) []int {
	out := make([]int, 0, end-start+1)
	for p := start; p <= end; p++ {
		out = append(out, p)
	}
	return out
}
