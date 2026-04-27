package dialer

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"golang.org/x/net/proxy"
)

// New returns a context-aware dialer. When proxyURL is non-empty it routes
// connections through the given SOCKS5 proxy (with optional auth).
// Accepted formats:
//
//	socks5://host:port
//	socks5://user:pass@host:port
//	host:port  (assumes socks5)
func New(proxyURL string, timeout time.Duration) (proxy.ContextDialer, error) {
	base := &net.Dialer{Timeout: timeout}
	if proxyURL == "" {
		return base, nil
	}

	addr, auth, err := parseProxyURL(proxyURL)
	if err != nil {
		return nil, err
	}

	d, err := proxy.SOCKS5("tcp", addr, auth, base)
	if err != nil {
		return nil, fmt.Errorf("socks5 dialer: %w", err)
	}

	cd, ok := d.(proxy.ContextDialer)
	if !ok {
		return nil, errors.New("socks5 dialer does not support DialContext")
	}
	return cd, nil
}

// DialContext is a convenience wrapper that creates a dialer and dials in one call.
func DialContext(ctx context.Context, proxyURL, network, address string, timeout time.Duration) (net.Conn, error) {
	d, err := New(proxyURL, timeout)
	if err != nil {
		return nil, err
	}
	return d.DialContext(ctx, network, address)
}

func parseProxyURL(raw string) (string, *proxy.Auth, error) {
	if !strings.Contains(raw, "://") {
		raw = "socks5://" + raw
	}

	parsed, err := url.Parse(raw)
	if err != nil {
		return "", nil, fmt.Errorf("parse proxy url: %w", err)
	}

	addr := parsed.Host
	if addr == "" && parsed.Opaque != "" {
		addr = parsed.Opaque
	}
	if addr == "" {
		return "", nil, errors.New("empty proxy address")
	}

	var auth *proxy.Auth
	if parsed.User != nil {
		username := parsed.User.Username()
		password, _ := parsed.User.Password()
		if username != "" {
			auth = &proxy.Auth{User: username, Password: password}
		}
	}

	return addr, auth, nil
}

// MaskCredentials replaces credentials in a proxy URL with **** for logging.
func MaskCredentials(proxyURL string) string {
	before, after, found := strings.Cut(proxyURL, "@")
	if !found {
		return proxyURL
	}
	schemeEnd := strings.Index(before, "://")
	if schemeEnd == -1 {
		return "****@" + after
	}
	return before[:schemeEnd+3] + "****@" + after
}
