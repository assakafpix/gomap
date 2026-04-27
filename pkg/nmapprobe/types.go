package nmapprobe

// Probe represents a single nmap service probe with its payload and associated matches.
type Probe struct {
	Name     string // e.g. "NULL", "GetRequest", "GenericLines"
	Protocol string // "TCP" or "UDP"
	Payload  []byte // decoded probe payload

	Rarity       int      // 1-9, lower = more common
	Ports        []int    // TCP ports this probe targets
	SSLPorts     []int    // ports where TLS should be tried first
	TotalWaitMS  int      // how long to wait for response
	TCPWrappedMS int      // timeout for tcpwrapped detection
	Fallback     []string // fallback probe names for match inheritance

	Matches     []Match // match directives
	SoftMatches []Match // softmatch directives (partial matches)
}

// Match represents a single match or softmatch directive.
type Match struct {
	Service string // service name (e.g. "ssh", "http", "mysql")

	// Pattern is the compiled PCRE-compatible regex.
	// We store the raw pattern string for compilation.
	PatternStr string
	Flags      string // regex flags: "i" (case-insensitive), "s" (dotall)

	// Extraction templates — may contain $1, $2, etc. backreferences.
	Product  string
	Version  string
	Info     string
	Hostname string
	OS       string
	CPEs     []string // raw CPE templates like "cpe:/a:openbsd:openssh:$2/"

	// IsSoft indicates this is a softmatch (partial detection).
	IsSoft bool
}

// MatchResult holds the extracted fields after a successful match.
type MatchResult struct {
	Service  string   `json:"service"`
	Product  string   `json:"product,omitempty"`
	Version  string   `json:"version,omitempty"`
	Info     string   `json:"info,omitempty"`
	Hostname string   `json:"hostname,omitempty"`
	OS       string   `json:"os,omitempty"`
	CPEs     []string `json:"cpes,omitempty"`

	ProbeName string `json:"probe_name"`
	IsSoft    bool   `json:"is_soft"`
}
