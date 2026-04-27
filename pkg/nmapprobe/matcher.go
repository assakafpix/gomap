package nmapprobe

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/dlclark/regexp2"
)

// CompiledMatch is a Match with its regex pre-compiled for fast matching.
type CompiledMatch struct {
	Match
	Re *regexp2.Regexp
}

// CompiledProbe is a Probe with all match patterns pre-compiled.
type CompiledProbe struct {
	Probe
	Matches     []CompiledMatch
	SoftMatches []CompiledMatch
}

// CompileProbes compiles all regex patterns in the probes.
// Patterns that fail to compile are silently skipped.
func CompileProbes(probes []Probe) []CompiledProbe {
	compiled := make([]CompiledProbe, 0, len(probes))
	for _, p := range probes {
		cp := CompiledProbe{
			Probe: p,
		}

		for _, m := range p.Matches {
			cm, err := compileMatch(m)
			if err != nil {
				continue
			}
			cp.Matches = append(cp.Matches, cm)
		}
		for _, m := range p.SoftMatches {
			cm, err := compileMatch(m)
			if err != nil {
				continue
			}
			cp.SoftMatches = append(cp.SoftMatches, cm)
		}

		compiled = append(compiled, cp)
	}
	return compiled
}

func compileMatch(m Match) (CompiledMatch, error) {
	var opts regexp2.RegexOptions = regexp2.RE2
	if strings.Contains(m.Flags, "i") {
		opts |= regexp2.IgnoreCase
	}
	if strings.Contains(m.Flags, "s") {
		opts |= regexp2.Singleline
	}

	re, err := regexp2.Compile(m.PatternStr, opts)
	if err != nil {
		// Retry without RE2 compatibility mode for patterns that use PCRE features.
		opts &^= regexp2.RE2
		re, err = regexp2.Compile(m.PatternStr, opts)
		if err != nil {
			return CompiledMatch{}, fmt.Errorf("compile %q: %w", m.PatternStr, err)
		}
	}

	re.MatchTimeout = -1 // no timeout during match; we control it at the dial level

	return CompiledMatch{Match: m, Re: re}, nil
}

// TryMatch attempts to match data against this compiled pattern.
// Returns nil if no match. On match, returns the result with backreferences resolved.
func (cm *CompiledMatch) TryMatch(data []byte, probeName string) *MatchResult {
	// Encode data as Latin-1 so that each byte maps to exactly one Unicode
	// code point (U+0000..U+00FF). This ensures that '.' in the regex matches
	// exactly one byte, not a multi-byte UTF-8 sequence. Without this, binary
	// patterns like '.{32}' fail when the data contains bytes > 127 because
	// regexp2 counts runes, not bytes.
	input := bytesToLatin1(data)

	m, err := cm.Re.FindStringMatch(input)
	if err != nil || m == nil {
		return nil
	}

	// Collect captured groups for backreference substitution.
	// Convert back from Latin-1 to raw bytes for the group values.
	groups := make([]string, m.GroupCount())
	for i := 0; i < m.GroupCount(); i++ {
		g := m.GroupByNumber(i)
		if g != nil {
			groups[i] = latin1ToBytes(g.String())
		}
	}

	result := &MatchResult{
		Service:   cm.Service,
		Product:   substituteBackrefs(cm.Product, groups),
		Version:   substituteBackrefs(cm.Version, groups),
		Info:      substituteBackrefs(cm.Info, groups),
		Hostname:  substituteBackrefs(cm.Hostname, groups),
		OS:        substituteBackrefs(cm.OS, groups),
		ProbeName: probeName,
		IsSoft:    cm.IsSoft,
	}

	for _, cpeTmpl := range cm.CPEs {
		resolved := substituteBackrefs(cpeTmpl, groups)
		if resolved != "" {
			result.CPEs = append(result.CPEs, resolved)
		}
	}

	return result
}

// substituteBackrefs replaces $1, $2, ... with captured group values.
func substituteBackrefs(template string, groups []string) string {
	if template == "" {
		return ""
	}
	if !strings.ContainsRune(template, '$') {
		return template
	}

	var b strings.Builder
	b.Grow(len(template))
	i := 0
	for i < len(template) {
		if template[i] == '$' && i+1 < len(template) {
			// Parse the group number ($1, $2, ..., $SUBST, etc.).
			j := i + 1
			if template[j] >= '1' && template[j] <= '9' {
				// Collect digits.
				k := j
				for k < len(template) && template[k] >= '0' && template[k] <= '9' {
					k++
				}
				num, _ := strconv.Atoi(template[j:k])
				if num < len(groups) {
					b.WriteString(groups[num])
				}
				i = k
				continue
			}
			// $SUBST(n,"old","new") — nmap substitution macro.
			if strings.HasPrefix(template[i:], "$SUBST(") {
				end := strings.Index(template[i:], ")")
				if end > 0 {
					b.WriteString(handleSubst(template[i:i+end+1], groups))
					i = i + end + 1
					continue
				}
			}
			// $P(n) — pass-through.
			if strings.HasPrefix(template[i:], "$P(") {
				end := strings.Index(template[i:], ")")
				if end > 0 {
					inner := template[i+3 : i+end]
					num, err := strconv.Atoi(inner)
					if err == nil && num < len(groups) {
						b.WriteString(groups[num])
					}
					i = i + end + 1
					continue
				}
			}
			// $I(n,"hex-replacement") — replace non-printable.
			if strings.HasPrefix(template[i:], "$I(") {
				end := strings.Index(template[i:], ")")
				if end > 0 {
					inner := template[i+3 : i+end]
					parts := strings.SplitN(inner, ",", 2)
					num, err := strconv.Atoi(parts[0])
					if err == nil && num < len(groups) {
						b.WriteString(cleanNonPrintable(groups[num]))
					}
					i = i + end + 1
					continue
				}
			}
			// Unknown $ sequence — output as-is.
			b.WriteByte('$')
			i++
		} else {
			b.WriteByte(template[i])
			i++
		}
	}
	return b.String()
}

// handleSubst handles $SUBST(n,"old","new") nmap substitution macros.
func handleSubst(s string, groups []string) string {
	// $SUBST(1,"-",".")
	inner := s[7 : len(s)-1] // strip $SUBST( and )
	parts := strings.SplitN(inner, ",", 3)
	if len(parts) < 3 {
		return ""
	}
	num, err := strconv.Atoi(parts[0])
	if err != nil || num >= len(groups) {
		return ""
	}
	old := strings.Trim(parts[1], `"`)
	new_ := strings.Trim(parts[2], `"`)
	return strings.ReplaceAll(groups[num], old, new_)
}

// bytesToLatin1 encodes raw bytes as a UTF-8 string where each byte maps to
// the corresponding Unicode code point U+0000..U+00FF (Latin-1 / ISO-8859-1).
// This gives a 1:1 byte-to-rune mapping so regex '.' matches exactly one byte.
func bytesToLatin1(data []byte) string {
	runes := make([]rune, len(data))
	for i, b := range data {
		runes[i] = rune(b)
	}
	return string(runes)
}

// latin1ToBytes converts a Latin-1 encoded string back to raw bytes.
func latin1ToBytes(s string) string {
	out := make([]byte, 0, len(s))
	for _, r := range s {
		if r < 256 {
			out = append(out, byte(r))
		} else {
			out = append(out, '?')
		}
	}
	return string(out)
}

// cleanNonPrintable replaces non-printable bytes with dots.
func cleanNonPrintable(s string) string {
	out := make([]byte, len(s))
	for i := range len(s) {
		if s[i] >= 32 && s[i] < 127 {
			out[i] = s[i]
		} else {
			out[i] = '.'
		}
	}
	return string(out)
}
