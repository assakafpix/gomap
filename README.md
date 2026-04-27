# gomap

**SOCKS5-native service detection — nmap-grade fingerprints, single Go binary.**

`gomap` is a service-version detector that speaks the same probe language as `nmap -sV` (it embeds the official `nmap-service-probes` database — 187 probes, 12,000+ signatures), but routes every TCP connection through a SOCKS5 proxy with auth. No companion container, no `proxychains`, no fork of nmap.

It exists because nmap's packet-crafting design can't ride on top of a SOCKS5 tunnel: nmap sends raw TCP/IP packets, SOCKS5 only carries `TCP CONNECT`. `gomap` does the connect scan + service detection slice — the part that *can* go through SOCKS5 — and does it with the same fingerprint quality.

## Why

You probably want this if any of these are true:

- You run port discovery through a SOCKS5 proxy (with `naabu`, `masscan-socks`, etc.) and you need service identification on the same path.
- You can't deploy nmap (containerized environments, no raw socket privileges, sandboxed CI).
- You want CPE 2.3 output ready to feed into a vulnerability database.
- You don't want to ship a companion container just to run `nmap -sV` over an SSH tunnel.

## Install

```bash
go install github.com/assakafpix/gomap@latest
```

Or build from source:

```bash
git clone https://github.com/assakafpix/gomap
cd gomap
go build -o gomap .
```

The binary is fully self-contained — the nmap probe database is embedded at compile time.

## Usage

The CLI mirrors nmap's flag shape so muscle memory transfers:

```bash
# Like nmap -sV
gomap -sV -p 22,80,443 scanme.nmap.org

# Top 100 most common ports through a SOCKS5 proxy
gomap --top-ports 100 --proxy socks5://user:pass@proxy:1080 10.0.0.1

# Full port range with maximum probe intensity
gomap -p- --version-intensity 9 target.example.com

# Pipe from naabu (the typical recon flow)
naabu -host target -silent | gomap --proxy socks5://proxy:1080

# Read targets from file (nmap's -iL)
gomap -iL targets.txt --proxy socks5://proxy:1080 -oJ
```

### Flags

| nmap-compatible | what it does |
|---|---|
| `-sV` | Enable service/version detection (default: open-port scan only, like nmap) |
| `-p 22,80,443` | Port list (also `-p1-1024`, `-p-` for all 65535) |
| `--top-ports N` | Scan the top N most common ports (10, 100, 1000) |
| `-iL file.txt` | Read targets from file |
| `--version-intensity 0-9` | Probe intensity (default 7, like nmap) |
| `--version-light` / `--version-all` | Aliases for intensity 2 / 9 |
| `--max-parallelism N` (or `-c N`) | Concurrent probes (default 50) |
| `--timeout 5s` | Per-probe timeout |
| `-V` / `-h` | Version / help |

| gomap-specific | what it does |
|---|---|
| `--proxy socks5://user:pass@host:port` | Route all probes through a SOCKS5 proxy |
| `-oJ` | JSON-line output (one result per line) |
| `--silent` | Suppress the banner |

### Target specification

```bash
gomap scanme.nmap.org              # bare host — needs -p or --top-ports
gomap scanme.nmap.org:22           # host:port — port from arg
gomap host1 host2 host3 -p 80,443  # multiple bare hosts × port list
gomap -iL targets.txt              # one host[:port] per line
naabu ... | gomap                  # stdin in naabu format
```

## Comparison with nmap

Tested on `scanme.nmap.org` and `scanme.sh` with default settings:

| Port | nmap `-sV` | gomap |
|---|---|---|
| 22 (OpenSSH) | OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 | OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 + 3 CPEs |
| 80 (Apache) | Apache httpd 2.4.7 ((Ubuntu)) | Apache httpd 2.4.7 + CPE |
| 80 (Go) | Golang net/http server | Golang net/http server + CPE |
| 443 (TLS) | ssl/http Golang net/http server | https [TLS] (Golang net/http server) + CPE |
| 9929 (nping-echo) | Nping echo | Nping echo |
| 31337 (filtered) | tcpwrapped | tcpwrapped |
| 53 (DNS, banner-shy) | tcpwrapped (gives up) | domain (correctly identifies DNS) |
| 445 (TLS 1.0 nginx) | ssl/microsoft-ds? (port-name guess) | https [TLS] (nginx 1.10.3) + CPE |

We sometimes do better — never worse — because:

- **Implicit NULL probe fallback** (per nmap's docs but not always exercised by their engine in tcpwrapped scenarios)
- **Latin-1 encoding of binary input** lets RE2/regexp2 match nmap patterns byte-for-byte (RE2 is rune-oriented, would otherwise miscount on bytes ≥ 0x80)
- **Honest "no detection"** — we don't emit a "guess" based on port number with a `?` suffix; an unfingerprinted port produces no false positive
- **TLS 1.0 acceptance** — Go's defaults reject pre-1.2; we relax this for the scanner only (we never trust certs anyway)
- **HTTP/1.1-only ALPN** during TLS probing — h2 negotiation would return binary HTTP/2 frames that no nmap pattern matches

## Limitations

- **TCP only.** No UDP service detection. Add a follow-up step if you need DNS/SNMP/NTP fingerprints.
- **No host discovery.** `gomap` assumes the port is open. Pair it with `naabu` (or any port scanner) for full pipeline.
- **No script engine.** No NSE equivalent. If you need post-detection enrichment (vuln checks, brute-forcing, screenshots) layer it separately — `nuclei`, `httpx`, etc.
- **No raw packet probes.** SYN scans, fragmentation, OS detection — fundamentally incompatible with SOCKS5; use nmap directly when you need them.

## Output format

Default: human-readable, one line per port:

```
target.com:22     ssh             (OpenSSH 9.6p1 Ubuntu 3ubuntu13.15)  cpe:2.3:a:openbsd:openssh:9.6p1:*:*:*:*:*:*:* ...
target.com:443    https           [TLS] (nginx 1.25.4)  cpe:2.3:a:igor_sysoev:nginx:1.25.4:*:*:*:*:*:*:*
target.com:5432   postgresql      (PostgreSQL 14.10 - Debian 14.10-1.pgdg110+1)  cpe:2.3:a:postgresql:postgresql:14.10:*:*:*:*:*:*:*
```

JSON (`-oJ`):

```json
{"host":"target.com","port":22,"open":true,"protocol":"ssh","tls":false,"product":"OpenSSH","version":"9.6p1 Ubuntu 3ubuntu13.15","info":"Ubuntu Linux; protocol 2.0","os":"Linux","cpes":["cpe:2.3:a:openbsd:openssh:9.6p1:*:*:*:*:*:*:*","cpe:2.3:o:canonical:ubuntu_linux:*:*:*:*:*:*:*:*","cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*"],"banner":"SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.15..","probes":["NULL"]}
```

The CPE field is in **CPE 2.3 format** ready for vulnerability lookups (NVD, OSV, etc.).

## How it works

1. **TCP liveness check**: open connection, drop. If it fails, the port is silently skipped (no false positives).
2. **Probe cascade**: send probes in priority order (by `rarity` and port association). Up to 187 probes, configurable via `--version-intensity`.
3. **Match engine**: every response is matched against the probe's hard matches → its explicit fallbacks → the NULL probe's matches → soft matches (in that order). Patterns use [regexp2](https://github.com/dlclark/regexp2) (PCRE-compatible) on Latin-1-encoded input for clean byte semantics.
4. **TLS fallback**: if a port responds to nothing, or returns the bare `ssl` match, we wrap probes in TLS (TLS 1.0+, http/1.1 ALPN) and re-run the cascade.
5. **tcpwrapped detection**: if every probe got 0 bytes AND the peer actively closed (EOF/RST), we report `tcpwrapped` (matches nmap's behavior).
6. **Generic fingerprints**: as a last resort, a small set of wire-shape regexes (`HTTP/1.x`, `SSH-`, `220 …SMTP`, etc.) recognize the protocol from the banner alone — no port-number guessing.

## Acknowledgments

- **The Nmap Project** — every signature in this tool comes from their `nmap-service-probes` database, the result of 25+ years of fingerprint contributions. See [nmap.org](https://nmap.org).
- **regexp2** — the [.NET-style regex library](https://github.com/dlclark/regexp2) by Doug Clark, which gives us PCRE features (backreferences, lookahead) on top of Go.

## License

`gomap`'s own code is licensed under **Apache-2.0** (see [LICENSE](LICENSE)).

The embedded `nmap-service-probes` file is licensed under the **Nmap Public Source License (NPSL)** — see [NOTICE](NOTICE) for full attribution and license text. The NPSL is GPL-compatible with additional terms regarding derivative works; please review it before forking or redistributing.
