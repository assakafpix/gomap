package nmapprobe

import (
	"regexp"
	"strings"
)

// Generic-fingerprint regexes. These are the last-resort patterns: when no
// nmap signature (hard or soft) fires but we did capture response data, we
// recognize the protocol from its wire-level shape.
//
// We use the stdlib regexp here (RE2, byte-oriented) because these
// patterns are simple and we want them to be fast — they're the hot path
// for unidentified banners. Unlike the nmap database patterns, none of
// these need PCRE features.
var (
	genericHTTPRe = regexp.MustCompile(`^HTTP/[0-9]\.[0-9] [0-9]{3}`)
	genericSSHRe  = regexp.MustCompile(`^SSH-[0-9]\.[0-9]+-`)
	genericFTPRe  = regexp.MustCompile(`(?i)^220[ -].*ftp`)
	genericSMTPRe = regexp.MustCompile(`(?i)^220[ -].*(?:e?smtp|mail)`)
	genericPOP3Re = regexp.MustCompile(`^\+OK`)
	genericIMAPRe = regexp.MustCompile(`(?i)^\* OK.*imap`)
	genericVNCRe  = regexp.MustCompile(`^RFB [0-9]{3}\.[0-9]{3}`)
)

// genericFingerprint identifies the protocol of a captured banner using
// wire-level shape — not port number. Used as the last-resort identifier
// when no nmap match (hard or soft) fired but we did capture data.
//
// We deliberately do NOT guess from the port number — that produces false
// positives on closed/silent services that happen to listen on a well-
// known port. Each pattern here describes a protocol's distinctive
// opening bytes, so a match is strong evidence even without a product.
//
// Returns the protocol name and an optional info string. Empty proto means
// no recognition.
func genericFingerprint(banner string) (proto, info string) {
	switch {
	case genericHTTPRe.MatchString(banner):
		return "http", ""
	case genericSSHRe.MatchString(banner):
		return "ssh", ""
	case genericFTPRe.MatchString(banner):
		return "ftp", ""
	case genericSMTPRe.MatchString(banner):
		return "smtp", ""
	case genericPOP3Re.MatchString(banner):
		return "pop3", ""
	case genericIMAPRe.MatchString(banner):
		return "imap", ""
	case genericVNCRe.MatchString(banner):
		return "vnc", ""
	case len(banner) >= 2 && strings.HasPrefix(banner, "\x05"):
		// SOCKS5 method-selection response: 0x05 followed by method byte.
		return "socks5", ""
	}
	return "", ""
}

// sanitize returns a printable representation of data, capped at max bytes,
// with non-printable bytes replaced by '.'. Used for storing captured
// banners in DetectResult so they remain human-readable in JSON/CLI output.
func sanitize(data []byte, max int) string {
	if len(data) > max {
		data = data[:max]
	}
	out := make([]byte, len(data))
	for i, b := range data {
		if b >= 32 && b < 127 {
			out[i] = b
		} else {
			out[i] = '.'
		}
	}
	return string(out)
}
