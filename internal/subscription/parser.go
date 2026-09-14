// Package subscription parses proxy subscription payloads into a normalized
// node representation that engine backends (sing-box, Xray) render to their
// own config formats.
//
// Node is deliberately backend-agnostic: internal/engine imports this package,
// never the reverse. Adding an Xray renderer must not require touching this file.
package subscription

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
)

// Protocol identifies the wire protocol of a node.
type Protocol string

const (
	ProtoBalance     Protocol = "loadbalance" // Local gateway group, not a sing-box outbound type.
	ProtoVLESS       Protocol = "vless"
	ProtoTrojan      Protocol = "trojan"
	ProtoVMess       Protocol = "vmess"
	ProtoShadowsocks Protocol = "shadowsocks"
	ProtoHysteria2   Protocol = "hysteria2"
)

// Security is the TLS layer in use.
type Security string

const (
	SecNone    Security = ""
	SecTLS     Security = "tls"
	SecReality Security = "reality"
)

// Transport is the stream transport carrying the protocol.
type Transport string

const (
	TransportTCP  Transport = "tcp"
	TransportWS   Transport = "ws"
	TransportGRPC Transport = "grpc"
	TransportHTTP Transport = "http"
)

// ErrUnsupportedScheme is returned for links whose scheme has no parser.
// Callers that tolerate mixed subscriptions should check for it with errors.Is
// and skip the entry rather than aborting the whole payload.
var ErrUnsupportedScheme = errors.New("subscription: unsupported scheme")

// Node is one normalized proxy server. Zero values mean "not specified by the
// link" — renderers must omit rather than guess, so a node that carried no SNI
// does not silently acquire one.
type Node struct {
	BalanceStrategy string   `json:",omitempty"`
	BalanceMembers  []string `json:",omitempty"` // stable IDs of private member snapshots
	BalanceTags     []string `json:"-"`          // resolved only for rendering
	// LocalVariant separates saved chain snapshots from provider node identity.
	LocalVariant  string `json:",omitempty"`
	ChainInternal bool   `json:",omitempty"`
	Protocol      Protocol
	Tag           string // display name from the link fragment; may be empty or duplicated
	Server        string
	Port          int

	// Credentials. Exactly one is meaningful per protocol:
	// VLESS/VMess use UUID, Trojan/Hysteria2 use Password,
	// Shadowsocks uses Method+Password.
	UUID     string
	Password string
	Method   string // shadowsocks cipher

	// VLESS only. "xtls-rprx-vision" or empty.
	Flow string

	// VMess only. Legacy alterId; 0 for AEAD-only servers.
	AlterID int

	Security    Security
	SNI         string
	ALPN        []string
	Insecure    bool
	Fingerprint string // uTLS fingerprint, e.g. "chrome"

	// Reality. Only meaningful when Security == SecReality.
	PublicKey string
	ShortID   string

	Transport   Transport
	Path        string // ws/http path, or grpc service name
	Host        string // ws/http Host header
	ServiceName string // grpc service name (kept distinct from Path)

	// Detour is the Tag of another Node to chain through (multi-hop). Empty
	// means dial directly. Maps to sing-box's outbound `detour` dial field:
	// this node's TCP connection to its own server is itself carried by the
	// Detour node, so traffic egresses at this node having transited Detour.
	//
	// Set by the operator, never by a subscription link -- no standard link
	// format carries chaining information. Renderers must validate the chain
	// (see ValidateChains): sing-box's `check` subcommand does NOT catch
	// cycles or dangling references, but `run` FATALs on them.
	Detour string
}

// Addr returns the dial target as host:port.
func (n Node) Addr() string {
	return net.JoinHostPort(n.Server, strconv.Itoa(n.Port))
}

// Validate reports whether the node has the minimum fields its protocol needs.
// Renderers should call this before emitting config: a node missing a UUID
// produces a config that fails validation at engine startup with a far less
// obvious error.
func (n Node) Validate() error {
	if n.Protocol == ProtoBalance {
		if n.BalanceStrategy != "" && n.BalanceStrategy != "hash" && n.BalanceStrategy != "latency" {
			return errors.New("unknown load balancing strategy")
		}
		if n.LocalVariant == "" || len(n.BalanceMembers) < 2 || len(n.BalanceMembers) > 32 || n.Detour != "" || n.ChainInternal {
			return errors.New("invalid load balanced configuration")
		}
		seen := map[string]bool{}
		for _, id := range n.BalanceMembers {
			if id == "" || seen[id] {
				return errors.New("invalid or duplicate balance member")
			}
			seen[id] = true
		}
		return nil
	}
	if n.Server == "" {
		return errors.New("missing server")
	}
	if n.Port <= 0 || n.Port > 65535 {
		return fmt.Errorf("invalid port %d", n.Port)
	}
	switch n.Protocol {
	case ProtoVLESS, ProtoVMess:
		if n.UUID == "" {
			return fmt.Errorf("%s: missing uuid", n.Protocol)
		}
	case ProtoTrojan, ProtoHysteria2:
		if n.Password == "" {
			return fmt.Errorf("%s: missing password", n.Protocol)
		}
	case ProtoShadowsocks:
		if n.Method == "" || n.Password == "" {
			return errors.New("shadowsocks: missing method or password")
		}
	case "":
		return errors.New("missing protocol")
	}
	if n.Security == SecReality && n.PublicKey == "" {
		return errors.New("reality: missing public key (pbk)")
	}
	return nil
}

// decodeBase64 tries every base64 flavour a subscription provider might use.
// Providers are inconsistent about padding and about std vs URL alphabet, and
// some serve plain text with no encoding at all, so this is intentionally
// permissive rather than strict.
func decodeBase64(s string) ([]byte, bool) {
	t := strings.TrimSpace(s)
	// Providers sometimes wrap the payload; newlines are not valid base64.
	t = strings.NewReplacer("\n", "", "\r", "", " ", "").Replace(t)
	if t == "" {
		return nil, false
	}
	for _, enc := range []*base64.Encoding{
		base64.StdEncoding,
		base64.RawStdEncoding,
		base64.URLEncoding,
		base64.RawURLEncoding,
	} {
		if b, err := enc.DecodeString(t); err == nil {
			return b, true
		}
	}
	return nil, false
}

// ParseSubscription decodes a raw subscription payload and parses every link in
// it. The payload may be base64-encoded (the common case) or already plain
// newline-separated links; both are accepted without a flag.
//
// Unparseable lines do not abort the batch — a single malformed node in a
// hundred-node subscription should not cost you the other ninety-nine. They are
// returned in errs for logging, paired by index with the input line.
func ParseSubscription(raw string) (nodes []Node, errs []error) {
	body := strings.TrimSpace(raw)
	if decoded, ok := decodeBase64(body); ok {
		// Only treat it as base64 if the result actually looks like links.
		// Random text can decode "successfully" into binary garbage.
		if s := string(decoded); strings.Contains(s, "://") {
			body = s
		}
	}

	for _, line := range strings.FieldsFunc(body, func(r rune) bool {
		return r == '\n' || r == '\r'
	}) {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
			continue
		}
		n, err := ParseLink(line)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		nodes = append(nodes, n)
	}
	return nodes, errs
}

// ParseLink parses a single proxy link.
func ParseLink(link string) (Node, error) {
	link = strings.TrimSpace(link)
	scheme, _, found := strings.Cut(link, "://")
	if !found {
		return Node{}, fmt.Errorf("subscription: not a proxy link: %.32q", link)
	}
	switch strings.ToLower(scheme) {
	case "vless":
		return parseVLESS(link)
	case "trojan":
		return parseTrojan(link)
	case "vmess":
		return parseVMess(link)
	case "ss":
		return parseShadowsocks(link)
	case "hysteria2", "hy2":
		return parseHysteria2(link)
	default:
		return Node{}, fmt.Errorf("%w: %q", ErrUnsupportedScheme, scheme)
	}
}

// applyQuery fills the TLS/transport fields shared by the URL-shaped protocols
// (vless, trojan, hysteria2). VMess carries the same information as JSON keys
// and is handled separately.
func applyQuery(n *Node, q url.Values) {
	switch strings.ToLower(q.Get("security")) {
	case "tls":
		n.Security = SecTLS
	case "reality":
		n.Security = SecReality
	case "none", "":
		n.Security = SecNone
	}

	n.SNI = firstNonEmpty(q.Get("sni"), q.Get("peer"), q.Get("host"))
	if alpn := q.Get("alpn"); alpn != "" {
		for _, a := range strings.Split(alpn, ",") {
			if a = strings.TrimSpace(a); a != "" {
				n.ALPN = append(n.ALPN, a)
			}
		}
	}
	n.Fingerprint = q.Get("fp")
	n.PublicKey = q.Get("pbk")
	n.ShortID = q.Get("sid")
	n.Flow = q.Get("flow")
	// allowInsecure appears under three spellings in the wild.
	n.Insecure = isTruthy(q.Get("allowInsecure")) ||
		isTruthy(q.Get("insecure")) || isTruthy(q.Get("allow_insecure"))

	// Reality implies TLS even when security= was omitted by a sloppy provider.
	if n.PublicKey != "" && n.Security == SecNone {
		n.Security = SecReality
	}

	switch strings.ToLower(firstNonEmpty(q.Get("type"), q.Get("net"))) {
	case "ws":
		n.Transport = TransportWS
		n.Path = q.Get("path")
		n.Host = firstNonEmpty(q.Get("host"), n.SNI)
	case "grpc":
		n.Transport = TransportGRPC
		n.ServiceName = firstNonEmpty(q.Get("serviceName"), q.Get("path"))
	case "http", "h2":
		n.Transport = TransportHTTP
		n.Path = q.Get("path")
		n.Host = q.Get("host")
	case "tcp", "":
		n.Transport = TransportTCP
	default:
		// Unknown transport: leave as TCP rather than emitting a transport
		// block the engine will reject.
		n.Transport = TransportTCP
	}
}

func parseVLESS(link string) (Node, error) {
	u, err := url.Parse(link)
	if err != nil {
		return Node{}, fmt.Errorf("vless: %w", err)
	}
	port, err := parsePort(u.Port())
	if err != nil {
		return Node{}, fmt.Errorf("vless: %w", err)
	}
	n := Node{
		Protocol: ProtoVLESS,
		Tag:      tagOf(u),
		Server:   u.Hostname(),
		Port:     port,
		UUID:     u.User.Username(),
	}
	applyQuery(&n, u.Query())
	return n, n.Validate()
}

func parseTrojan(link string) (Node, error) {
	u, err := url.Parse(link)
	if err != nil {
		return Node{}, fmt.Errorf("trojan: %w", err)
	}
	port, err := parsePort(u.Port())
	if err != nil {
		return Node{}, fmt.Errorf("trojan: %w", err)
	}
	// url.Parse percent-decodes Username but NOT the password half, so read it
	// explicitly; trojan passwords routinely contain reserved characters.
	pw := u.User.Username()
	if p, ok := u.User.Password(); ok && p != "" {
		pw = p
	}
	n := Node{
		Protocol: ProtoTrojan,
		Tag:      tagOf(u),
		Server:   u.Hostname(),
		Port:     port,
		Password: pw,
	}
	applyQuery(&n, u.Query())
	// Trojan is TLS-by-definition; providers frequently omit security=tls.
	if n.Security == SecNone {
		n.Security = SecTLS
	}
	return n, n.Validate()
}

func parseHysteria2(link string) (Node, error) {
	u, err := url.Parse(link)
	if err != nil {
		return Node{}, fmt.Errorf("hysteria2: %w", err)
	}
	// Hysteria2 defaults to 443 when the link omits a port.
	port := 443
	if p := u.Port(); p != "" {
		if port, err = parsePort(p); err != nil {
			return Node{}, fmt.Errorf("hysteria2: %w", err)
		}
	}
	pw := u.User.Username()
	if p, ok := u.User.Password(); ok && p != "" {
		pw = pw + ":" + p
	}
	n := Node{
		Protocol: ProtoHysteria2,
		Tag:      tagOf(u),
		Server:   u.Hostname(),
		Port:     port,
		Password: pw,
	}
	applyQuery(&n, u.Query())
	if n.Security == SecNone {
		n.Security = SecTLS
	}
	return n, n.Validate()
}

// vmessLink is the JSON object inside a base64'd vmess:// link.
// Numeric fields arrive as either JSON numbers or strings depending on the
// generating client, hence json.Number.
type vmessLink struct {
	Insecure json.RawMessage `json:"allowInsecure"`
	V        json.Number     `json:"v"`
	PS       string          `json:"ps"`
	Add      string          `json:"add"`
	Port     json.Number     `json:"port"`
	ID       string          `json:"id"`
	Aid      json.Number     `json:"aid"`
	Scy      string          `json:"scy"`
	Net      string          `json:"net"`
	Type     string          `json:"type"`
	Host     string          `json:"host"`
	Path     string          `json:"path"`
	TLS      string          `json:"tls"`
	SNI      string          `json:"sni"`
	ALPN     string          `json:"alpn"`
	FP       string          `json:"fp"`
}

func parseVMess(link string) (Node, error) {
	payload := strings.TrimPrefix(link, "vmess://")
	decoded, ok := decodeBase64(payload)
	if !ok {
		return Node{}, errors.New("vmess: body is not valid base64")
	}
	var v vmessLink
	if err := json.Unmarshal(decoded, &v); err != nil {
		return Node{}, fmt.Errorf("vmess: %w", err)
	}
	port, err := parsePort(v.Port.String())
	if err != nil {
		return Node{}, fmt.Errorf("vmess: %w", err)
	}
	aid := 0
	if v.Aid != "" {
		aid, _ = strconv.Atoi(v.Aid.String())
	}
	n := Node{
		Protocol:    ProtoVMess,
		Insecure:    isTruthy(strings.Trim(string(v.Insecure), `"`)),
		Tag:         v.PS,
		Server:      v.Add,
		Port:        port,
		UUID:        v.ID,
		AlterID:     aid,
		Method:      v.Scy, // vmess "security" cipher, e.g. "auto"
		SNI:         firstNonEmpty(v.SNI, v.Host),
		Fingerprint: v.FP,
	}
	if strings.EqualFold(v.TLS, "tls") {
		n.Security = SecTLS
	}
	if v.ALPN != "" {
		for _, a := range strings.Split(v.ALPN, ",") {
			if a = strings.TrimSpace(a); a != "" {
				n.ALPN = append(n.ALPN, a)
			}
		}
	}
	switch strings.ToLower(v.Net) {
	case "ws":
		n.Transport, n.Path, n.Host = TransportWS, v.Path, v.Host
	case "grpc":
		n.Transport, n.ServiceName = TransportGRPC, v.Path
	case "h2", "http":
		n.Transport, n.Path, n.Host = TransportHTTP, v.Path, v.Host
	default:
		n.Transport = TransportTCP
	}
	return n, n.Validate()
}

// parseShadowsocks handles both SIP002 (ss://base64(method:pass)@host:port)
// and the legacy fully-base64'd form (ss://base64(method:pass@host:port)).
func parseShadowsocks(link string) (Node, error) {
	body := strings.TrimPrefix(link, "ss://")
	tag := ""
	if i := strings.LastIndex(body, "#"); i >= 0 {
		tag, _ = url.QueryUnescape(body[i+1:])
		body = body[:i]
	}
	// Strip plugin params; sing-box needs them modelled separately and a
	// silently-dropped plugin is better than a wrong one.
	if i := strings.Index(body, "?"); i >= 0 {
		body = body[:i]
	}

	// Legacy: no "@" after decoding means the whole thing was encoded.
	if !strings.Contains(body, "@") {
		decoded, ok := decodeBase64(body)
		if !ok {
			return Node{}, errors.New("ss: body is not valid base64")
		}
		body = string(decoded)
	}

	at := strings.LastIndex(body, "@")
	if at < 0 {
		return Node{}, errors.New("ss: malformed link (no userinfo separator)")
	}
	userinfo, hostport := body[:at], body[at+1:]

	// SIP002 encodes only the userinfo half.
	if !strings.Contains(userinfo, ":") {
		if decoded, ok := decodeBase64(userinfo); ok {
			userinfo = string(decoded)
		}
	}
	method, password, found := strings.Cut(userinfo, ":")
	if !found {
		return Node{}, errors.New("ss: userinfo missing method:password")
	}
	if unescaped, err := url.QueryUnescape(password); err == nil {
		password = unescaped
	}

	host, portStr, err := net.SplitHostPort(hostport)
	if err != nil {
		return Node{}, fmt.Errorf("ss: %w", err)
	}
	port, err := parsePort(portStr)
	if err != nil {
		return Node{}, fmt.Errorf("ss: %w", err)
	}
	n := Node{
		Protocol:  ProtoShadowsocks,
		Tag:       tag,
		Server:    host,
		Port:      port,
		Method:    method,
		Password:  password,
		Transport: TransportTCP,
	}
	return n, n.Validate()
}

func tagOf(u *url.URL) string {
	// net/url already percent-decodes fragments. A literal plus is not a space.
	return u.Fragment
}

func parsePort(s string) (int, error) {
	if s == "" {
		return 0, errors.New("missing port")
	}
	p, err := strconv.Atoi(s)
	if err != nil {
		return 0, fmt.Errorf("invalid port %q", s)
	}
	if p <= 0 || p > 65535 {
		return 0, fmt.Errorf("port out of range: %d", p)
	}
	return p, nil
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

func isTruthy(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "1", "true", "yes":
		return true
	}
	return false
}

// DedupeTags makes every node tag unique and non-empty in place. Engine configs
// key outbounds by tag, so duplicates from a provider silently collapse
// outbounds and break the selector; this is required before rendering.
//
// Detour references are rewritten alongside the rename. Renaming a tag without
// this would silently repoint a chain at the wrong hop (or at nothing), and
// because sing-box's `check` does not validate detour targets, the breakage
// would only surface as a FATAL at `run` time.
//
// A Detour naming a tag that was duplicated resolves to the FIRST node that
// held that tag, which is the only interpretation available once the name is
// ambiguous.
func DedupeTags(nodes []Node) {
	seen := make(map[string]int, len(nodes))
	// rename maps an original tag to the tag assigned to its first occurrence.
	rename := make(map[string]string, len(nodes))

	for i := range nodes {
		orig := strings.TrimSpace(nodes[i].Tag)
		base := orig
		if base == "" {
			base = fmt.Sprintf("%s-%s", nodes[i].Protocol, nodes[i].Server)
		}
		tag := base
		if k := seen[base]; k > 0 {
			tag = fmt.Sprintf("%s-%d", base, k+1)
		}
		seen[base]++
		nodes[i].Tag = tag
		if orig != "" {
			if _, ok := rename[orig]; !ok {
				rename[orig] = tag
			}
		}
	}

	for i := range nodes {
		if d := nodes[i].Detour; d != "" {
			if to, ok := rename[d]; ok {
				nodes[i].Detour = to
			}
		}
	}
}

// ValidateChains checks every Detour reference resolves and that the detour
// graph is acyclic.
//
// This is not optional hardening. Verified against sing-box 1.14.0:
// `sing-box check` ACCEPTS a config with a self-detour, a multi-hop cycle, or a
// detour naming a nonexistent tag, but `sing-box run` dies at startup with
// "circular outbound dependency: a -> b -> c -> a" or
// "dependency[ghost] not found for outbound[a]". A caller that validates with
// check, stops the running engine, then starts the new one would strand the
// gateway with TPROXY rules loaded and no proxy listening.
func ValidateChains(nodes []Node) error {
	byTag := make(map[string]int, len(nodes))
	for i, n := range nodes {
		byTag[n.Tag] = i
	}

	// Colour states for iterative DFS: 0 unvisited, 1 on current path, 2 done.
	const (
		white = 0
		grey  = 1
		black = 2
	)
	colour := make([]int, len(nodes))

	for start := range nodes {
		if colour[start] != white {
			continue
		}
		// Walk the chain from start. Each node has at most one outgoing edge,
		// so the "graph" is a functional graph and a plain walk suffices --
		// no recursion or explicit stack needed.
		var path []string
		i := start
		for {
			if colour[i] == grey {
				// Re-entered the path we are currently walking: cycle.
				return fmt.Errorf("subscription: circular detour chain: %s -> %s",
					strings.Join(path, " -> "), nodes[i].Tag)
			}
			if colour[i] == black {
				break // already proven acyclic
			}
			colour[i] = grey
			path = append(path, nodes[i].Tag)

			d := nodes[i].Detour
			if d == "" {
				break
			}
			if d == nodes[i].Tag {
				return fmt.Errorf("subscription: node %q detours through itself", nodes[i].Tag)
			}
			next, ok := byTag[d]
			if !ok {
				return fmt.Errorf("subscription: node %q detours through unknown tag %q",
					nodes[i].Tag, d)
			}
			i = next
		}
		// Everything on this path is proven acyclic.
		for _, tag := range path {
			colour[byTag[tag]] = black
		}
	}
	return nil
}

// ChainOf returns the full hop sequence for the node with the given tag,
// starting at that node and following Detour to the outermost hop. The last
// element is the hop that talks to the internet's far side first.
// Returns nil if the tag is unknown. Assumes ValidateChains has passed;
// it bails out at len(nodes) hops rather than looping forever.
func ChainOf(nodes []Node, tag string) []string {
	byTag := make(map[string]int, len(nodes))
	for i, n := range nodes {
		byTag[n.Tag] = i
	}
	i, ok := byTag[tag]
	if !ok {
		return nil
	}
	var chain []string
	for hop := 0; hop <= len(nodes); hop++ {
		chain = append(chain, nodes[i].Tag)
		d := nodes[i].Detour
		if d == "" {
			return chain
		}
		next, ok := byTag[d]
		if !ok {
			return chain
		}
		i = next
	}
	return chain
}
