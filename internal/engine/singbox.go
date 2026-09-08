// Package engine renders proxy-engine configuration and supervises the engine
// process. Bare-metal only: the Go binary runs as a systemd unit on the Pi and
// owns sing-box as a child process.
package engine

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"

	"proxy-manager/internal/subscription"
)

// Defaults align with scripts/tproxy/tproxy.conf. TPROXY_PORT there must equal
// DefaultTProxyPort here, or interception lands on a closed port and every LAN
// connection hangs.
const (
	DefaultTProxyPort = 7892
	DefaultListen     = "::" // dual-stack; nftables ruleset is v4-only for now
	DefaultTag        = "tproxy-in"
	DefaultSelector   = "proxy"
	DefaultDirect     = "direct"
	// DefaultURLTest is the auto-switch group's tag. It is the first member of
	// the selector, so the UI toggles auto vs manual by selecting this tag or a
	// node tag via the Clash API -- no config regeneration needed.
	DefaultURLTest = "auto"

	// DefaultProbeURL matches internal/tester so the auto-switch and the
	// operator-visible latency column measure against the same endpoint.
	DefaultProbeURL = "http://cp.cloudflare.com/generate_204"

	// DefaultResolverTag is the dns.servers[].tag for the system resolver
	// (AdGuard Home on this host). Used as route.default_domain_resolver.
	DefaultResolverTag = "sys"
	// DefaultBootstrapResolverTag resolves rule-set hosts. It is a plain UDP
	// server reached through DefaultFetchOutbound, so it works before any
	// proxy is up.
	DefaultBootstrapResolverTag = "boot"
	// DefaultFetchOutbound is a direct outbound dedicated to rule-set
	// downloads and bootstrap DNS. It must carry at least one dial setting:
	// sing-box 1.14 rejects a detour to a bare, unconfigured direct outbound
	// with "detour to an empty direct outbound makes no sense".
	DefaultFetchOutbound = "direct-fetch"
	// DefaultBootstrapDNS is the upstream for DefaultBootstrapResolverTag.
	// A public resolver on purpose: rule-set fetches must not depend on
	// AdGuard being healthy, since AdGuard runs in Docker on the same host
	// this gateway is bringing up.
	DefaultBootstrapDNS = "1.1.1.1"

	defaultStopTimeout  = 8 * time.Second
	defaultCheckTimeout = 15 * time.Second
)

// Options configures config generation and process supervision.
type Options struct {
	// BinaryPath is the sing-box executable. Default: resolved from PATH.
	BinaryPath string
	// ConfigPath is where config.json is written. Default:
	// /etc/proxy-manager/singbox/config.json
	ConfigPath string

	TProxyPort int
	Listen     string
	InboundTag string

	// RoutingMark is written to every outbound as routing_mark. Set it to the
	// TPROXY_FWMARK from tproxy.conf ONLY if you later tighten the nftables
	// OUTPUT chain to intercept locally-generated traffic; with the current
	// bypass-only OUTPUT chain, 0 (omitted) is correct.
	RoutingMark int

	LogLevel string
	// DNS is emitted verbatim when non-nil. Left nil by default: the DNS schema
	// changed in 1.12 and AdGuard Home already owns LAN DNS on this host.
	DNS *DNSOptions

	// --- Iran bypass ---

	// IranBypass emits the Chocolate4U Iran rule-sets and routes matching
	// traffic to `direct`. On by default via NewManager; set DisableIranBypass
	// to opt out.
	DisableIranBypass bool
	// BlockIranAds additionally rejects the Iranian ads/tracker rule-set.
	// Off by default: AdGuard Home already filters ads on this host, and
	// double-filtering makes attribution harder when something is wrongly
	// blocked.
	BlockIranAds bool
	// RuleSetDetour is the outbound used to DOWNLOAD rule-sets. Must be
	// reachable without routing being up; defaults to "direct".
	RuleSetDetour string
	// LegacyDownloadDetour emits the pre-1.14 `download_detour` spelling
	// instead of `http_client: {detour: ...}`. Set this only for sing-box
	// older than 1.14, which does not understand http_client. On 1.14+ the
	// legacy form still works but logs a deprecation warning and is removed
	// in 1.16.
	LegacyDownloadDetour bool
	// CacheFilePath enables experimental.cache_file so remote rule-sets survive
	// restarts instead of re-downloading ~350 KB each time. Empty disables it.
	CacheFilePath string

	// --- control API ---

	// ClashAPIListen enables experimental.clash_api on this address (e.g.
	// "127.0.0.1:9090"). Empty omits the block entirely.
	//
	// This is how the active node is switched without a restart: the API layer
	// PUTs to /proxies/<selector>. Without it, changing the selection means
	// regenerating config and restarting the engine, which drops every live LAN
	// connection. Bind loopback only -- the API can switch outbounds and read
	// traffic counters.
	ClashAPIListen string
	// ClashAPISecret is the bearer token for the Clash API. Strongly recommended
	// whenever ClashAPIListen is not on loopback.
	ClashAPISecret string

	// --- auto-switch ---

	// DisableAutoSwitch omits the urltest group. When omitted the selector
	// contains only node tags, so the UI's auto option disappears.
	DisableAutoSwitch bool
	// AutoSwitchURL overrides the urltest probe target.
	AutoSwitchURL string
	// AutoSwitchInterval is how often urltest re-measures. Default 3m.
	AutoSwitchInterval time.Duration
	// AutoSwitchTolerance in ms; a candidate must beat the incumbent by more
	// than this to win. Default 50. Too low causes flapping between nodes whose
	// latency differs by less than normal jitter.
	AutoSwitchTolerance int

	// LegacyTransparentField emits `"transparent": true` on the tproxy inbound.
	// This is NOT a valid sing-box field and current versions reject the config
	// with "unknown field transparent". Provided only so the failure can be
	// reproduced rather than taken on trust. Leave false.
	LegacyTransparentField bool

	StopTimeout time.Duration
	Logger      *slog.Logger

	// OnExit fires when sing-box exits for any reason, including a crash.
	// err is nil on a clean exit. Called from the reaper goroutine, so it must
	// not call back into the Manager synchronously.
	OnExit func(err error)
}

func (o *Options) setDefaults() {
	if o.TProxyPort == 0 {
		o.TProxyPort = DefaultTProxyPort
	}
	if o.Listen == "" {
		o.Listen = DefaultListen
	}
	if o.InboundTag == "" {
		o.InboundTag = DefaultTag
	}
	if o.ConfigPath == "" {
		o.ConfigPath = "/etc/proxy-manager/singbox/config.json"
	}
	if o.BinaryPath == "" {
		o.BinaryPath = "sing-box"
	}
	if o.LogLevel == "" {
		o.LogLevel = "info"
	}
	if o.StopTimeout == 0 {
		o.StopTimeout = defaultStopTimeout
	}
	if o.Logger == nil {
		o.Logger = slog.Default()
	}
	if o.RuleSetDetour == "" {
		o.RuleSetDetour = DefaultDirect
	}
	if o.AutoSwitchURL == "" {
		o.AutoSwitchURL = DefaultProbeURL
	}
	if o.AutoSwitchInterval == 0 {
		o.AutoSwitchInterval = 3 * time.Minute
	}
	if o.AutoSwitchTolerance == 0 {
		o.AutoSwitchTolerance = 50
	}
}

// Manager renders config and supervises one sing-box process.
// All exported methods are safe for concurrent use.
type Manager struct {
	opts Options

	mu     sync.Mutex
	cmd    *exec.Cmd
	cancel context.CancelFunc
	exited chan struct{} // closed by reap() when the process is gone
}

// NewManager returns a Manager. It does not touch the filesystem or start
// anything; call Apply or Start.
func NewManager(opts Options) *Manager {
	opts.setDefaults()
	return &Manager{opts: opts}
}

// ConfigPath exposes the rendered config location (useful for logging).
func (m *Manager) ConfigPath() string { return m.opts.ConfigPath }

// BuildConfig renders a full sing-box config from nodes.
//
// nodes is mutated: tags are deduplicated in place, because sing-box keys
// outbounds by tag and a provider repeating "🇺🇸 US" twelve times would
// otherwise collapse into one outbound and break the selector.
func (m *Manager) BuildConfig(nodes []subscription.Node) (*Config, error) {
	if len(nodes) == 0 {
		return nil, errors.New("engine: no nodes to build config from")
	}
	subscription.DedupeTags(nodes)

	// Validate the detour graph BEFORE anything is written. sing-box's `check`
	// subcommand accepts cycles and dangling detour targets (verified against
	// 1.14.0) but `run` FATALs on them -- and Apply's order is
	// check -> stop -> start, so a bad chain would stop a working engine and
	// then fail to start the new one, leaving the LAN blackholed with TPROXY
	// rules loaded.
	if err := subscription.ValidateChains(nodes); err != nil {
		return nil, fmt.Errorf("engine: %w", err)
	}

	inbound := &TProxyInbound{
		Type:       "tproxy",
		Tag:        m.opts.InboundTag,
		Listen:     m.opts.Listen,
		ListenPort: m.opts.TProxyPort,
		UDPTimeout: "5m",
		// Network omitted => both tcp and udp, which is what the nftables
		// ruleset steers (meta l4proto { tcp, udp }).
	}
	if m.opts.LegacyTransparentField {
		inbound.Transparent = true
		m.opts.Logger.Warn("emitting invalid 'transparent' field on tproxy inbound; " +
			"sing-box will reject this config")
	}

	outbounds := []any{
		&DirectOutbound{Type: "direct", Tag: DefaultDirect, RoutingMark: m.opts.RoutingMark},
	}
	// A second direct outbound dedicated to rule-set downloads and bootstrap
	// DNS. Emitted before the node outbounds so ordering stays readable.
	// DomainResolver both points the fetch at the system resolver AND makes the
	// outbound non-empty, without which 1.14 refuses it as a detour target.
	// Emitted in BOTH modes: legacy download_detour also names this tag, and a
	// download_detour pointing at a nonexistent outbound fails at startup with
	// "dependency not found".
	if !m.opts.DisableIranBypass {
		outbounds = append(outbounds, &DirectOutbound{
			Type: "direct", Tag: DefaultFetchOutbound,
			DomainResolver: DefaultResolverTag,
		})
	}
	var tags []string
	var skipped []error
	renderedTags := make(map[string]bool, len(nodes))
	for _, n := range nodes {
		ob, err := m.buildOutbound(n)
		if err != nil {
			// One unsupported node must not cost the whole subscription.
			skipped = append(skipped, err)
			continue
		}
		outbounds = append(outbounds, ob)
		tags = append(tags, n.Tag)
		renderedTags[n.Tag] = true
	}
	for _, err := range skipped {
		m.opts.Logger.Warn("skipping node", "err", err)
	}
	if len(tags) == 0 {
		return nil, fmt.Errorf("engine: no usable nodes: %w", errors.Join(skipped...))
	}

	// A node whose detour target was skipped would render a dangling reference
	// that `check` accepts and `run` rejects. Drop the detour and log it: losing
	// the extra hop is strictly better than an engine that will not start.
	for i := range nodes {
		if d := nodes[i].Detour; d != "" && !renderedTags[d] {
			m.opts.Logger.Warn("clearing detour to unusable node",
				"node", nodes[i].Tag, "detour", d)
			nodes[i].Detour = ""
			// Re-render this outbound without the detour.
			for j, ob := range outbounds {
				if taggedAs(ob, nodes[i].Tag) {
					fixed, err := m.buildOutbound(nodes[i])
					if err == nil {
						outbounds[j] = fixed
					}
					break
				}
			}
		}
	}

	// Auto-switch group. Members are the node tags only -- never "direct" and
	// never the selector, which would make the group's own health depend on the
	// group. Emitted before the selector so the selector can reference it.
	//
	// Chained nodes are excluded from urltest: the group measures each member
	// independently, and a chain's latency is dominated by its upstream hop, so
	// including a 3-hop chain alongside single-hop nodes reliably picks the
	// wrong winner. Chains stay manually selectable.
	selectorMembers := make([]string, 0, len(tags)+1)
	autoMembers := make([]string, 0, len(tags))
	for _, n := range nodes {
		if !renderedTags[n.Tag] {
			continue
		}
		if n.Detour == "" {
			autoMembers = append(autoMembers, n.Tag)
		}
	}

	// An empty urltest is a hard startup failure ("missing tags", verified on
	// 1.14.0), so the group is omitted when every node is chained.
	autoEnabled := !m.opts.DisableAutoSwitch && len(autoMembers) > 0
	if autoEnabled {
		outbounds = append(outbounds, &URLTestOutbound{
			Type:      "urltest",
			Tag:       DefaultURLTest,
			Outbounds: autoMembers,
			URL:       m.opts.AutoSwitchURL,
			Interval:  durationString(m.opts.AutoSwitchInterval),
			Tolerance: m.opts.AutoSwitchTolerance,
			// Existing connections keep their old node when the pick changes:
			// tearing down live streams on every latency wobble is worse than a
			// slightly stale route for connections already in flight.
			InterruptExistConnections: false,
		})
		// First member => the selector's default, so a fresh install
		// auto-switches until the operator picks a node explicitly. The UI
		// toggles auto vs manual by selecting "auto" or a node tag through the
		// Clash API; no config regeneration required.
		selectorMembers = append(selectorMembers, DefaultURLTest)
	} else if m.opts.DisableAutoSwitch {
		m.opts.Logger.Debug("auto-switch disabled by option")
	} else {
		m.opts.Logger.Warn("auto-switch omitted: no unchained nodes to test")
	}
	selectorMembers = append(selectorMembers, tags...)

	outbounds = append(outbounds, &SelectorOutbound{
		Type:      "selector",
		Tag:       DefaultSelector,
		Outbounds: selectorMembers,
		Default:   selectorMembers[0],
	})

	rules := []RouteRule{
		// LOOP BREAKER -- must stay first, ahead of even `sniff`.
		//
		// A connection whose destination is BOTH a local/private address AND
		// our own TPROXY port is, by definition, this engine talking to its own
		// listener. Left unhandled it is matched by the `ip_is_private` rule
		// below and sent to `direct`, which dials 127.0.0.1:TPROXY_PORT, which
		// the tproxy inbound accepts, which routes to `direct` again: an
		// unbounded userspace connection storm that looks like
		//
		//   inbound/tproxy[tproxy-in]: inbound connection to 127.0.0.1:7892
		//   outbound/direct[direct]:   outbound connection to 127.0.0.1:7892
		//
		// and saturates the Pi. NO nftables rule can prevent this: a loopback
		// dial from a local process never traverses the prerouting hook, so
		// `iifname "lo"` / `fib daddr type local` / bypass_daddrs are all
		// bypassed. It has to be caught here, in routing.
		//
		// Matching daddr AND port (rather than port alone) keeps a LAN client's
		// legitimate connection to some public host on 7892 working. Both loop
		// variants are covered, because `ip_is_private` is true for loopback as
		// well as RFC1918 -- so a dial to 127.0.0.1:7892 and one to
		// PI_LAN_IP:7892 are both rejected.
		//
		// Default reject method (TCP RST / ICMP unreachable) is deliberate: the
		// dialer learns immediately instead of holding the connection until
		// timeout.
		{
			IPIsPrivate: true,
			Port:        []int{m.opts.TProxyPort},
			Action:      "reject",
		},
		// Sniff first: without it, routing sees only IPs, because TPROXY
		// hands us the original destination address and no SNI/Host. Every
		// domain-based rule below (including the Iran geosite bypass) depends
		// on this having run.
		// This is the 1.11+ replacement for the removed inbound `sniff`.
		{
			Inbound: []string{m.opts.InboundTag},
			Action:  "sniff",
			Sniffer: []string{"http", "tls", "quic", "dns"},
			Timeout: "300ms",
		},
		// Hijack DNS from LAN clients into the engine so a proxied
		// client cannot resolve around the tunnel. AdGuard still
		// serves LAN DNS directly -- that traffic never reaches this
		// inbound, because the nftables `fib daddr type local` rule
		// accepts it before interception.
		{
			Protocol: []string{"dns"},
			Action:   "route",
			Outbound: DefaultSelector,
		},
		// RFC1918 / link-local destinations stay off the proxy. Belt
		// and braces: the nftables bypass_daddrs set already drops
		// these before they reach sing-box.
		{
			IPIsPrivate: true,
			Action:      "route",
			Outbound:    DefaultDirect,
		},
	}

	route := &RouteOptions{
		Final:               DefaultSelector,
		AutoDetectInterface: true,
	}
	dns := m.opts.DNS
	if !m.opts.DisableIranBypass {
		route.RuleSet = IranRuleSets(DefaultFetchOutbound, DefaultBootstrapResolverTag,
			m.opts.BlockIranAds, m.opts.LegacyDownloadDetour)

		// Rule-set downloads need three things that are easy to get wrong; all
		// three were found by RUNNING a generated config on 1.14.0, not by
		// reading docs, because `sing-box check` accepts every broken variant:
		//
		//  1. A dedicated direct outbound with at least one dial setting. A
		//     detour to a bare `direct` is a startup FATAL ("detour to an empty
		//     direct outbound makes no sense").
		//  2. route.default_domain_resolver. Without it 1.14 aborts with
		//     "missing route.default_domain_resolver ... is deprecated".
		//  3. A bootstrap DNS server reached through that direct outbound. A
		//     `type: local` server is not enough here: with route.final pointing
		//     at the proxy selector, the engine's own lookups go through
		//     unreachable proxy nodes and time out, so startup fails before any
		//     proxy exists to make them reachable.
		route.DefaultDomainResolver = &DomainResolverOptions{Server: DefaultResolverTag}
		if dns == nil {
			dns = &DNSOptions{Servers: []any{
				map[string]any{"type": "local", "tag": DefaultResolverTag},
				map[string]any{
					"type":   "udp",
					"tag":    DefaultBootstrapResolverTag,
					"server": DefaultBootstrapDNS,
					"detour": DefaultFetchOutbound,
				},
			}}
		}
		// Appended after sniff/DNS/private so those keep priority; the Iran
		// rules themselves are internally ordered (ads reject before bypass).
		rules = append(rules, iranRules(m.opts.BlockIranAds)...)
	}
	route.Rules = rules

	cfg := &Config{
		Log:       &LogOptions{Level: m.opts.LogLevel, Timestamp: true},
		DNS:       dns,
		Inbounds:  []any{inbound},
		Outbounds: outbounds,
		Route:     route,
	}
	if m.opts.CacheFilePath != "" || m.opts.ClashAPIListen != "" {
		cfg.Experimental = &ExperimentalOptions{}
	}
	if m.opts.CacheFilePath != "" {
		// Persists downloaded rule-sets across restarts; without it each start
		// re-fetches ~350 KB and the proxy waits on the network to come up.
		// Enabling cache_file also makes the selector's current pick survive a
		// restart; see CacheFileOptions for why there is no explicit flag.
		cfg.Experimental.CacheFile = &CacheFileOptions{
			Enabled: true,
			Path:    m.opts.CacheFilePath,
		}
	}
	if m.opts.ClashAPIListen != "" {
		cfg.Experimental.ClashAPI = &ClashAPIOptions{
			ExternalController: m.opts.ClashAPIListen,
			Secret:             m.opts.ClashAPISecret,
		}
		if m.opts.CacheFilePath == "" {
			// Without cache_file there is nowhere to persist the pick, so every
			// restart silently reverts to the urltest group.
			m.opts.Logger.Warn("clash_api enabled without a cache file; " +
				"node selection will not survive an engine restart")
		}
	}
	return cfg, nil
}

// ClashAPIAddr reports the configured Clash API listen address, empty when
// disabled. The API layer uses this to build its control client.
func (m *Manager) ClashAPIAddr() string { return m.opts.ClashAPIListen }

// ClashAPISecret reports the configured Clash API bearer token, if any.
func (m *Manager) ClashAPISecret() string { return m.opts.ClashAPISecret }

// TProxyPort reports the port the engine's tproxy inbound listens on. The API
// layer probes this to confirm the engine is actually accepting connections
// before it installs the nftables ruleset -- loading interception rules while
// nothing listens blackholes the LAN.
func (m *Manager) TProxyPort() int { return m.opts.TProxyPort }

// durationString renders a Go duration in the form sing-box accepts.
func durationString(d time.Duration) string {
	if d <= 0 {
		return ""
	}
	return d.String()
}

func (m *Manager) buildOutbound(n subscription.Node) (any, error) {
	if err := n.Validate(); err != nil {
		return nil, fmt.Errorf("node %q: %w", n.Tag, err)
	}
	tls := buildTLS(n)
	tr := buildTransport(n)

	// Per the 1.14 dial-fields docs: when `detour` is set, all other dial fields
	// on that outbound are IGNORED. Emitting routing_mark alongside detour would
	// therefore be a silent no-op that reads like it works -- so the mark is
	// dropped explicitly and the reason recorded here. The chain's egress mark
	// comes from the outermost hop, which has no detour of its own.
	mark := m.opts.RoutingMark
	if n.Detour != "" {
		mark = 0
	}

	switch n.Protocol {
	case subscription.ProtoVLESS:
		return &VLESSOutbound{
			Type: "vless", Tag: n.Tag, Server: n.Server, ServerPort: n.Port,
			UUID: n.UUID, Flow: n.Flow, TLS: tls, Transport: tr,
			Detour: n.Detour, RoutingMark: mark,
		}, nil
	case subscription.ProtoTrojan:
		return &TrojanOutbound{
			Type: "trojan", Tag: n.Tag, Server: n.Server, ServerPort: n.Port,
			Password: n.Password, TLS: tls, Transport: tr,
			Detour: n.Detour, RoutingMark: mark,
		}, nil
	case subscription.ProtoVMess:
		return &VMessOutbound{
			Type: "vmess", Tag: n.Tag, Server: n.Server, ServerPort: n.Port,
			UUID: n.UUID, Security: n.Method, AlterID: n.AlterID,
			TLS: tls, Transport: tr, Detour: n.Detour, RoutingMark: mark,
		}, nil
	case subscription.ProtoShadowsocks:
		return &ShadowsocksOutbound{
			Type: "shadowsocks", Tag: n.Tag, Server: n.Server, ServerPort: n.Port,
			Method: n.Method, Password: n.Password,
			Detour: n.Detour, RoutingMark: mark,
		}, nil
	case subscription.ProtoHysteria2:
		return &Hysteria2Outbound{
			Type: "hysteria2", Tag: n.Tag, Server: n.Server, ServerPort: n.Port,
			Password: n.Password, TLS: tls, Detour: n.Detour, RoutingMark: mark,
		}, nil
	default:
		return nil, fmt.Errorf("unsupported protocol %q", n.Protocol)
	}
}

// RenderOutbound converts a node to a sing-box outbound with no Manager
// options applied. Exported for internal/tester, which needs to render probe
// configs without importing Manager state (and without a routing_mark, which
// would be wrong for a loopback SOCKS probe).
func RenderOutbound(n subscription.Node) (any, error) {
	var zero Manager
	return zero.buildOutbound(n)
}

// taggedAs reports whether a rendered outbound carries the given tag.
func taggedAs(ob any, tag string) bool {
	switch o := ob.(type) {
	case *VLESSOutbound:
		return o.Tag == tag
	case *TrojanOutbound:
		return o.Tag == tag
	case *VMessOutbound:
		return o.Tag == tag
	case *ShadowsocksOutbound:
		return o.Tag == tag
	case *Hysteria2Outbound:
		return o.Tag == tag
	default:
		return false
	}
}

func buildTLS(n subscription.Node) *TLSOptions {
	if n.Security != subscription.SecTLS && n.Security != subscription.SecReality {
		return nil
	}
	t := &TLSOptions{
		Enabled:    true,
		ServerName: n.SNI,
		Insecure:   n.Insecure,
		ALPN:       n.ALPN,
	}
	if n.SNI == "" {
		// Fall back to the dial host, matching what clients do; an empty
		// server_name with enabled TLS fails verification.
		t.ServerName = n.Server
	}
	if n.Fingerprint != "" {
		t.UTLS = &UTLSOptions{Enabled: true, Fingerprint: n.Fingerprint}
	}
	if n.Security == subscription.SecReality {
		t.Reality = &RealityOptions{Enabled: true, PublicKey: n.PublicKey, ShortID: n.ShortID}
		// Reality does its own verification; insecure is meaningless and
		// utls is mandatory, so default the fingerprint when absent.
		t.Insecure = false
		if t.UTLS == nil {
			t.UTLS = &UTLSOptions{Enabled: true, Fingerprint: "chrome"}
		}
	}
	return t
}

func buildTransport(n subscription.Node) *TransportOptions {
	switch n.Transport {
	case subscription.TransportWS:
		t := &TransportOptions{Type: "ws", Path: n.Path}
		if n.Host != "" {
			t.Headers = map[string][]string{"Host": {n.Host}}
		}
		return t
	case subscription.TransportGRPC:
		return &TransportOptions{Type: "grpc", ServiceName: n.ServiceName}
	case subscription.TransportHTTP:
		t := &TransportOptions{Type: "http", Path: n.Path}
		if n.Host != "" {
			t.Host = []string{n.Host}
		}
		return t
	default:
		return nil // plain TCP: omit the transport block entirely
	}
}

// WriteConfig marshals cfg and writes it atomically at ConfigPath with 0600.
// 0600 is deliberate: the file contains UUIDs and passwords, and sing-box runs
// as root here. The temp-file-and-rename means a crash mid-write can never
// leave a half-written config that fails to parse on the next boot.
func (m *Manager) WriteConfig(cfg *Config) error {
	buf, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("engine: marshal config: %w", err)
	}
	buf = append(buf, '\n')

	dir := filepath.Dir(m.opts.ConfigPath)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("engine: mkdir %s: %w", dir, err)
	}
	tmp, err := os.CreateTemp(dir, ".config-*.json")
	if err != nil {
		return fmt.Errorf("engine: temp file: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op after a successful rename

	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return fmt.Errorf("engine: chmod temp: %w", err)
	}
	if _, err := tmp.Write(buf); err != nil {
		tmp.Close()
		return fmt.Errorf("engine: write temp: %w", err)
	}
	// fsync before rename: on a Pi with an SD card and sudden power loss, a
	// rename can otherwise land pointing at unflushed data.
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("engine: sync temp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("engine: close temp: %w", err)
	}
	if err := os.Rename(tmpName, m.opts.ConfigPath); err != nil {
		return fmt.Errorf("engine: rename into place: %w", err)
	}
	return nil
}

// Check runs `sing-box check -c <config>` and returns the engine's own
// validation error. Always call this before Start: a bad config makes sing-box
// exit immediately, and with TPROXY rules loaded that means a silently dead
// LAN rather than a visible error.
func (m *Manager) Check(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, defaultCheckTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, m.opts.BinaryPath, "check", "-c", m.opts.ConfigPath)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	cmd.Stdout = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("engine: config check failed: %w: %s", err, bytes.TrimSpace(stderr.Bytes()))
	}
	return nil
}

// Running reports whether a supervised process is currently alive.
func (m *Manager) Running() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.cmd != nil
}

// Pid returns the running process id, or 0.
func (m *Manager) Pid() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.cmd == nil || m.cmd.Process == nil {
		return 0
	}
	return m.cmd.Process.Pid
}

// Start launches sing-box. ctx bounds only the startup handshake, not the
// process lifetime: a request-scoped context must not kill the engine when the
// HTTP handler returns, so the process is tied to an internal context cancelled
// by Stop.
func (m *Manager) Start(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.cmd != nil {
		return errors.New("engine: already running")
	}
	if _, err := os.Stat(m.opts.ConfigPath); err != nil {
		return fmt.Errorf("engine: config not readable: %w", err)
	}

	runCtx, cancel := context.WithCancel(context.Background())
	cmd := exec.CommandContext(runCtx, m.opts.BinaryPath,
		"run", "-c", m.opts.ConfigPath, "-D", filepath.Dir(m.opts.ConfigPath))

	// Own process group + parent-death signal. See procattr_linux.go for why
	// both are needed and which one actually guarantees cleanup.
	cmd.SysProcAttr = sysProcAttr()

	// WaitDelay bounds how long Wait blocks after runCtx is cancelled if
	// sing-box ignores the kill and holds its stdio pipes open (Go 1.20+).
	cmd.WaitDelay = 3 * time.Second

	logw := newLogWriter(m.opts.Logger)
	cmd.Stdout = logw
	cmd.Stderr = logw

	if err := cmd.Start(); err != nil {
		cancel()
		return fmt.Errorf("engine: start %s: %w", m.opts.BinaryPath, err)
	}
	m.cmd = cmd
	m.cancel = cancel
	m.exited = make(chan struct{})
	m.opts.Logger.Info("sing-box started", "pid", cmd.Process.Pid, "config", m.opts.ConfigPath)

	go m.reap(cmd, cancel, m.exited)
	return nil
}

// reap waits for the process and clears state so Start can run again.
func (m *Manager) reap(cmd *exec.Cmd, cancel context.CancelFunc, exited chan struct{}) {
	err := cmd.Wait()
	cancel()

	m.mu.Lock()
	if m.cmd == cmd { // guard against a race with a fast Stop/Start cycle
		m.cmd = nil
		m.cancel = nil
		m.exited = nil
	}
	m.mu.Unlock()
	close(exited)

	if err != nil {
		m.opts.Logger.Warn("sing-box exited", "err", err)
	} else {
		m.opts.Logger.Info("sing-box exited cleanly")
	}
	if m.opts.OnExit != nil {
		m.opts.OnExit(err)
	}
}

// Stop terminates sing-box: SIGTERM to the whole process group, escalating to
// SIGKILL after StopTimeout. The group signal matters because sing-box may
// have spawned helpers; signalling only the leader can orphan them holding the
// TPROXY port, and the next Start then fails with "address already in use".
func (m *Manager) Stop(ctx context.Context) error {
	m.mu.Lock()
	cmd, cancel, exited := m.cmd, m.cancel, m.exited
	m.mu.Unlock()
	if cmd == nil || cmd.Process == nil {
		return nil // already stopped; idempotent
	}

	if err := terminateGroup(cmd.Process.Pid); err != nil {
		if !errors.Is(err, errors.ErrUnsupported) {
			m.opts.Logger.Debug("group SIGTERM failed, signalling leader", "err", err)
		}
		_ = cmd.Process.Signal(sigTerm())
	}

	timer := time.NewTimer(m.opts.StopTimeout)
	defer timer.Stop()
	select {
	case <-exited:
		return nil
	case <-timer.C:
		m.opts.Logger.Warn("sing-box did not exit on SIGTERM, sending SIGKILL",
			"timeout", m.opts.StopTimeout)
		if cancel != nil {
			cancel() // CommandContext's Cancel sends Kill to the leader
		}
		_ = killGroup(cmd.Process.Pid)
		<-exited
		return nil
	case <-ctx.Done():
		// Caller gave up waiting. The process is still going; do not clear
		// state, so a later Stop can finish the job.
		return ctx.Err()
	}
}

// Apply is the full reconciliation path: render, persist, validate, restart.
// Restart happens only after Check passes, so a bad subscription update leaves
// the previously-working engine running rather than taking the LAN down.
func (m *Manager) Apply(ctx context.Context, nodes []subscription.Node) error {
	cfg, err := m.BuildConfig(nodes)
	if err != nil {
		return err
	}
	if err := m.WriteConfig(cfg); err != nil {
		return err
	}
	if err := m.Check(ctx); err != nil {
		return err
	}
	if m.Running() {
		if err := m.Stop(ctx); err != nil {
			return fmt.Errorf("engine: stop before restart: %w", err)
		}
	}
	return m.Start(ctx)
}

// logWriter forwards engine stdout/stderr line-by-line into slog, so journald
// gets structured records instead of one blob per read.
type logWriter struct {
	log *slog.Logger
	buf bytes.Buffer
}

func newLogWriter(l *slog.Logger) io.Writer { return &logWriter{log: l} }

func (w *logWriter) Write(p []byte) (int, error) {
	w.buf.Write(p)
	for {
		line, err := w.buf.ReadString('\n')
		if err != nil {
			// Partial line: put it back and wait for the rest.
			w.buf.WriteString(line)
			break
		}
		if line = trimEOL(line); line != "" {
			w.log.Info(line, "src", "sing-box")
		}
	}
	return len(p), nil
}

func trimEOL(s string) string {
	return string(bytes.TrimRight([]byte(s), "\r\n \t"))
}
