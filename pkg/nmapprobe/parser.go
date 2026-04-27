package nmapprobe

import (
	"bufio"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// Parse reads an nmap-service-probes file and returns all parsed probes.
func Parse(r io.Reader) ([]Probe, error) {
	var probes []Probe
	var current *Probe

	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 1024*1024), 1024*1024) // 1MB line buffer

	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := scanner.Text()

		// Skip comments and blank lines.
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Skip Exclude directive.
		if strings.HasPrefix(line, "Exclude ") {
			continue
		}

		// Probe directive starts a new probe.
		if strings.HasPrefix(line, "Probe ") {
			if current != nil {
				probes = append(probes, *current)
			}
			p, err := parseProbe(line)
			if err != nil {
				return nil, fmt.Errorf("line %d: %w", lineNum, err)
			}
			current = &p
			continue
		}

		if current == nil {
			continue
		}

		if strings.HasPrefix(line, "match ") {
			m, err := parseMatch(line, false)
			if err != nil {
				// Skip unparseable match lines rather than failing entirely.
				continue
			}
			current.Matches = append(current.Matches, m)
		} else if strings.HasPrefix(line, "softmatch ") {
			m, err := parseMatch(line, true)
			if err != nil {
				continue
			}
			current.SoftMatches = append(current.SoftMatches, m)
		} else if strings.HasPrefix(line, "rarity ") {
			r, _ := strconv.Atoi(strings.TrimPrefix(line, "rarity "))
			current.Rarity = r
		} else if strings.HasPrefix(line, "ports ") {
			current.Ports = parsePorts(strings.TrimPrefix(line, "ports "))
		} else if strings.HasPrefix(line, "sslports ") {
			current.SSLPorts = parsePorts(strings.TrimPrefix(line, "sslports "))
		} else if strings.HasPrefix(line, "totalwaitms ") {
			current.TotalWaitMS, _ = strconv.Atoi(strings.TrimPrefix(line, "totalwaitms "))
		} else if strings.HasPrefix(line, "tcpwrappedms ") {
			current.TCPWrappedMS, _ = strconv.Atoi(strings.TrimPrefix(line, "tcpwrappedms "))
		} else if strings.HasPrefix(line, "fallback ") {
			current.Fallback = strings.Split(strings.TrimPrefix(line, "fallback "), ",")
		}
	}

	if current != nil {
		probes = append(probes, *current)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scanner: %w", err)
	}
	return probes, nil
}

// parseProbe parses "Probe TCP NULL q||" or "Probe TCP GetRequest q|GET / HTTP/1.0\r\n\r\n|"
func parseProbe(line string) (Probe, error) {
	// Format: Probe <protocol> <name> q|<payload>|
	parts := strings.SplitN(line, " ", 4)
	if len(parts) < 4 {
		return Probe{}, fmt.Errorf("invalid probe line: %s", line)
	}

	protocol := parts[1]
	name := parts[2]

	// Extract payload between q| and |
	payloadStr := parts[3]
	payload, err := parseQuotedPayload(payloadStr)
	if err != nil {
		return Probe{}, fmt.Errorf("parse probe payload: %w", err)
	}

	return Probe{
		Name:        name,
		Protocol:    protocol,
		Payload:     payload,
		Rarity:      1, // default
		TotalWaitMS: 5000,
	}, nil
}

// parseQuotedPayload extracts the payload from q|...|
func parseQuotedPayload(s string) ([]byte, error) {
	if !strings.HasPrefix(s, "q|") {
		return nil, fmt.Errorf("expected q| prefix, got: %.20s", s)
	}
	// Find last |
	end := strings.LastIndex(s, "|")
	if end <= 1 {
		return nil, fmt.Errorf("missing closing |")
	}
	raw := s[2:end]
	return decodeNmapEscapes(raw), nil
}

// decodeNmapEscapes handles \r \n \t \xHH \0 escape sequences in nmap payloads.
func decodeNmapEscapes(s string) []byte {
	var buf []byte
	i := 0
	for i < len(s) {
		if s[i] == '\\' && i+1 < len(s) {
			switch s[i+1] {
			case 'r':
				buf = append(buf, '\r')
				i += 2
			case 'n':
				buf = append(buf, '\n')
				i += 2
			case 't':
				buf = append(buf, '\t')
				i += 2
			case '\\':
				buf = append(buf, '\\')
				i += 2
			case '0':
				buf = append(buf, 0)
				i += 2
			case 'a':
				buf = append(buf, '\a')
				i += 2
			case 'x':
				if i+3 < len(s) {
					b, err := strconv.ParseUint(s[i+2:i+4], 16, 8)
					if err == nil {
						buf = append(buf, byte(b))
						i += 4
						continue
					}
				}
				buf = append(buf, s[i])
				i++
			default:
				buf = append(buf, s[i])
				i++
			}
		} else {
			buf = append(buf, s[i])
			i++
		}
	}
	return buf
}

// parseMatch parses a match or softmatch line.
// Format: match <service> m|<pattern>|[flags] [p/<product>/] [v/<version>/] [i/<info>/] [h/<hostname>/] [o/<os>/] [cpe:/<cpe>/]
func parseMatch(line string, isSoft bool) (Match, error) {
	var prefix string
	if isSoft {
		prefix = "softmatch "
	} else {
		prefix = "match "
	}
	rest := strings.TrimPrefix(line, prefix)

	// Extract service name (first word).
	spaceIdx := strings.IndexByte(rest, ' ')
	if spaceIdx < 0 {
		return Match{}, fmt.Errorf("no service name")
	}
	service := rest[:spaceIdx]
	rest = rest[spaceIdx+1:]

	// Extract pattern: m|...|[flags]
	pattern, flags, afterPattern, err := extractDelimited(rest, 'm')
	if err != nil {
		return Match{}, fmt.Errorf("parse pattern: %w", err)
	}

	m := Match{
		Service:    service,
		PatternStr: pattern,
		Flags:      flags,
		IsSoft:     isSoft,
	}

	// Parse remaining fields: p/.../ v/.../ i/.../ h/.../ o/.../ cpe:/.../
	parseFields(afterPattern, &m)

	return m, nil
}

// extractDelimited extracts content between delimiters like m|...|flags
// The delimiter character after 'm' determines the delimiter pair.
func extractDelimited(s string, prefix byte) (content, flags, remainder string, err error) {
	if len(s) < 2 || s[0] != prefix {
		return "", "", "", fmt.Errorf("expected '%c' prefix", prefix)
	}
	delim := s[1]

	// Find closing delimiter, handling escape sequences.
	i := 2
	for i < len(s) {
		if s[i] == '\\' && i+1 < len(s) {
			i += 2 // skip escaped character
			continue
		}
		if s[i] == delim {
			content = s[2:i]
			// Flags follow immediately after closing delimiter (before space).
			rest := s[i+1:]
			flagEnd := 0
			for flagEnd < len(rest) && rest[flagEnd] != ' ' && rest[flagEnd] != '\t' {
				flagEnd++
			}
			flags = rest[:flagEnd]
			if flagEnd < len(rest) {
				remainder = strings.TrimLeft(rest[flagEnd:], " \t")
			}
			return content, flags, remainder, nil
		}
		i++
	}
	return "", "", "", fmt.Errorf("unclosed delimiter '%c'", delim)
}

// parseFields extracts p/.../ v/.../ i/.../ h/.../ o/.../ cpe:/.../ from the remainder.
func parseFields(s string, m *Match) {
	for len(s) > 0 {
		s = strings.TrimLeft(s, " \t")
		if len(s) == 0 {
			break
		}

		switch {
		case strings.HasPrefix(s, "p/") || strings.HasPrefix(s, "p|"):
			val, rest := extractField(s[1:])
			m.Product = val
			s = rest
		case strings.HasPrefix(s, "v/") || strings.HasPrefix(s, "v|"):
			val, rest := extractField(s[1:])
			m.Version = val
			s = rest
		case strings.HasPrefix(s, "i/") || strings.HasPrefix(s, "i|"):
			val, rest := extractField(s[1:])
			m.Info = val
			s = rest
		case strings.HasPrefix(s, "h/") || strings.HasPrefix(s, "h|"):
			val, rest := extractField(s[1:])
			m.Hostname = val
			s = rest
		case strings.HasPrefix(s, "o/") || strings.HasPrefix(s, "o|"):
			val, rest := extractField(s[1:])
			m.OS = val
			s = rest
		case strings.HasPrefix(s, "d/") || strings.HasPrefix(s, "d|"):
			_, rest := extractField(s[1:])
			s = rest
		case strings.HasPrefix(s, "cpe:/"):
			val, rest := extractCPE(s)
			if val != "" {
				m.CPEs = append(m.CPEs, val)
			}
			s = rest
		default:
			// Unknown field, skip to next space.
			idx := strings.IndexAny(s, " \t")
			if idx < 0 {
				s = ""
			} else {
				s = s[idx:]
			}
		}
	}
}

// extractField extracts content from /.../ starting after the field prefix letter.
// s starts at the delimiter: "/content/" or "|content|"
func extractField(s string) (string, string) {
	if len(s) == 0 {
		return "", ""
	}
	delim := s[0]
	i := 1
	for i < len(s) {
		if s[i] == '\\' && i+1 < len(s) {
			i += 2
			continue
		}
		if s[i] == delim {
			return s[1:i], strings.TrimLeft(s[i+1:], " \t")
		}
		i++
	}
	// No closing delimiter found — take rest as value.
	return s[1:], ""
}

// extractCPE extracts a cpe:/ directive. Format: cpe:/<type>:<vendor>:<product>[:<version>][/[flag]]
func extractCPE(s string) (string, string) {
	// Skip "cpe:/"
	s = s[4:]
	delim := s[0]
	i := 1
	for i < len(s) {
		if s[i] == '\\' && i+1 < len(s) {
			i += 2
			continue
		}
		if s[i] == delim {
			val := "cpe:" + s[:i]
			rest := s[i+1:]
			// Skip optional trailing flag character (like 'a').
			if len(rest) > 0 && rest[0] != ' ' && rest[0] != '\t' && rest[0] != 'c' {
				rest = rest[1:]
			}
			return val, strings.TrimLeft(rest, " \t")
		}
		i++
	}
	return "cpe:" + s, ""
}

// parsePorts parses a comma-separated port list with optional ranges.
func parsePorts(s string) []int {
	var ports []int
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if strings.Contains(part, "-") {
			rangeParts := strings.SplitN(part, "-", 2)
			start, err1 := strconv.Atoi(rangeParts[0])
			end, err2 := strconv.Atoi(rangeParts[1])
			if err1 != nil || err2 != nil {
				continue
			}
			// For large ranges, just store start and end.
			if end-start > 1000 {
				ports = append(ports, start, end)
			} else {
				for p := start; p <= end; p++ {
					ports = append(ports, p)
				}
			}
		} else {
			p, err := strconv.Atoi(part)
			if err == nil {
				ports = append(ports, p)
			}
		}
	}
	return ports
}
