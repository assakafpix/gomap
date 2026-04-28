package nmapprobe

import (
	"context"
	"fmt"
	"regexp"
	"time"
)

// amqpProtoHeader is the AMQP 0-9-1 protocol header. Sending it to an AMQP
// broker prompts the broker to reply with a `connection.start` frame whose
// server-properties table includes product and version strings.
//
// 'A','M','Q','P', 0x00, 0x00, 0x09, 0x01
var amqpProtoHeader = []byte{0x41, 0x4d, 0x51, 0x50, 0x00, 0x00, 0x09, 0x01}

// AMQP wire format for server-properties: each entry is
//
//	<key-length:1> <key> 'S' <value-length:4> <value>
//
// We pull "product", "version", "platform", and "cluster_name" out of the
// connection.start payload with simple regex over the raw bytes — no full
// AMQP parser, since we only want a few well-known string fields.
var (
	amqpProductRe  = regexp.MustCompile(`\x07productS....([A-Za-z][A-Za-z0-9 ._/+-]{1,63})`)
	amqpVersionRe  = regexp.MustCompile(`\x07versionS....([\w.+-]{1,32})`)
	amqpPlatformRe = regexp.MustCompile(`\x08platformS....([\w.+/ -]{1,64})`)
	amqpClusterRe  = regexp.MustCompile(`\x0ccluster_nameS....([\w.@-]{1,64})`)
)

// enrichAMQP runs a real AMQP handshake against host:port and updates result
// with product/version from the broker's connection.start frame.
//
// The base nmap match for AMQP only fires on the 8-byte protocol header
// (which a broker sends back to a non-AMQP probe like GetRequest). To get
// the actual product+version, we have to be the one initiating AMQP — the
// broker only sends connection.start in response to an AMQP handshake.
//
// This is a niche but valuable enrichment: nmap reports "RabbitMQ 3.13.7"
// where its public probe DB has no such match line — they parse the AMQP
// frame inside nmap's C source. We do the same with regexes.
func (e *Engine) enrichAMQP(ctx context.Context, host string, port int, result *DetectResult) {
	target := fmt.Sprintf("%s:%d", host, port)
	ctx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()

	conn, err := e.Dialer.DialContext(ctx, "tcp", target)
	if err != nil {
		return
	}
	defer conn.Close()

	conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
	if _, err := conn.Write(amqpProtoHeader); err != nil {
		return
	}

	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	data, _ := readWithErr(conn)
	if len(data) == 0 {
		return
	}

	if m := amqpProductRe.FindSubmatch(data); m != nil {
		result.Product = string(m[1])
	}
	if m := amqpVersionRe.FindSubmatch(data); m != nil {
		result.Version = string(m[1])
	}

	// Compose info line from platform + cluster_name when available.
	var info string
	if m := amqpPlatformRe.FindSubmatch(data); m != nil {
		info = string(m[1])
	}
	if m := amqpClusterRe.FindSubmatch(data); m != nil {
		if info != "" {
			info += "; "
		}
		info += "cluster: " + string(m[1])
	}
	if info != "" && result.Info == "" {
		result.Info = info
	}

	// CPE for RabbitMQ specifically. Other AMQP brokers don't have the same
	// fingerprint shape so we don't try to be clever.
	if result.Product == "RabbitMQ" && result.Version != "" {
		result.CPEs = append(result.CPEs,
			"cpe:2.3:a:pivotal_software:rabbitmq:"+result.Version+":*:*:*:*:*:*:*")
	}

	result.Probes = append(result.Probes, "amqp-handshake")
}
