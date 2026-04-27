package main

import (
	"fmt"
	"strings"

	"github.com/assakafpix/gomap/pkg/nmapprobe"
)

// printResult writes one detected service to stdout in the default
// human-readable format:
//
//	host:port  protocol [TLS] (Product Version)  cpe:2.3:... cpe:2.3:...
//
// JSON output is handled directly by main.emit() with json.Encoder.
func printResult(r nmapprobe.DetectResult) {
	proto := r.Protocol
	if proto == "" {
		proto = "unknown"
	}

	tlsTag := ""
	if r.TLS {
		tlsTag = " [TLS]"
	}

	detail := ""
	if r.Product != "" {
		detail = " (" + r.Product
		if r.Version != "" {
			detail += " " + r.Version
		}
		detail += ")"
	}

	cpeStr := ""
	if len(r.CPEs) > 0 {
		cpeStr = "  " + strings.Join(r.CPEs, " ")
	}

	fmt.Printf("%s:%-5d  %-15s%s%s%s\n", r.Host, r.Port, proto, tlsTag, detail, cpeStr)
}
