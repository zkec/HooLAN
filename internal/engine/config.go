package engine

// sing-box config schema, verified against the 1.13 docs:
//
//   inbound/tproxy      -> type, tag, network + shared Listen fields
//   shared/listen       -> listen, listen_port, ..., routing_mark (1.12+)
//   route/rule_action   -> action: sniff | resolve | route | reject
//
// IMPORTANT: there is NO "transparent" field on the tproxy inbound. The field
// belongs to Xray's dokodemo-door (as "followRedirect"); sing-box's tproxy
// inbound IS the transparent proxy, so the concept is implicit in the type.
// sing-box rejects unknown fields, so emitting it fails `sing-box check` with
// "unknown field transparent". Options.LegacyTransparentField exists only to
// reproduce that failure on demand -- see its doc comment.
//
// Likewise inbound-level `sniff`/`sniff_override_destination`/`domain_strategy`
// were deprecated in 1.11.0 and REMOVED in 1.13.0. Sniffing is emitted here as
// a route rule action, which is the only form current sing-box accepts.

// Config is the top-level sing-box configuration document.
type Config struct {
	Log          *LogOptions          `json:"log,omitempty"`
	DNS          *DNSOptions          `json:"dns,omitempty"`
	Inbounds     []any                `json:"inbounds"`
	Outbounds    []any                `json:"outbounds"`
	Route        *RouteOptions        `json:"route,omitempty"`
	Experimental *ExperimentalOptions `json:"experimental,omitempty"`
}

type LogOptions struct {
	Disabled  bool   `json:"disabled,omitempty"`
	Level     string `json:"level,omitempty"`
	Output    string `json:"output,omitempty"`
	Timestamp bool   `json:"timestamp,omitempty"`
}

// TProxyInbound is the interception inbound the nftables ruleset targets.
// Field set is exactly what the 1.13 schema allows.
type TProxyInbound struct {
	Type       string `json:"type"` // "tproxy"
	Tag        string `json:"tag"`
	Listen     string `json:"listen"` // "::" dual-stack, "0.0.0.0" v4-only
	ListenPort int    `json:"listen_port"`
	Network    string `json:"network,omitempty"` // "tcp", "udp", or "" for both
	UDPTimeout string `json:"udp_timeout,omitempty"`

	// Deliberately invalid; only set when Options.LegacyTransparentField is on.
	Transparent bool `json:"transparent,omitempty"`
}

// DNSOptions contains the modern typed DNS servers and rules used by the
// ordinary resolver and optional FakeDNS. No legacy dns.fakeip block is emitted.
type DNSOptions struct {
	Servers  []any  `json:"servers,omitempty"`
	Rules    []any  `json:"rules,omitempty"`
	Final    string `json:"final,omitempty"`
	Strategy string `json:"strategy,omitempty"`
}

type RouteOptions struct {
	Rules                 []RouteRule            `json:"rules,omitempty"`
	RuleSet               []RuleSet              `json:"rule_set,omitempty"`
	Final                 string                 `json:"final,omitempty"`
	AutoDetectInterface   bool                   `json:"auto_detect_interface,omitempty"`
	DefaultMark           int                    `json:"default_mark,omitempty"`
	DefaultDomainResolver *DomainResolverOptions `json:"default_domain_resolver,omitempty"`
}

// RuleSet is a route rule-set source (sing-box 1.8.0+). This replaces the
// removed `geoip` / `geosite` config sections and their route-rule matchers.
//
// Two ways to say "fetch this through outbound X":
//
//	HTTPClient     -- {"detour": "direct"}, the modern form (1.14.0+)
//	DownloadDetour -- "direct", deprecated in 1.14.0, REMOVED in 1.16.0
//
// Verified by running a generated config on 1.14.0: DownloadDetour logs
// "legacy `download_detour` remote rule-set option is deprecated in sing-box
// 1.14.0 and will be removed in sing-box 1.16.0". Set exactly one -- see
// Options.LegacyDownloadDetour for choosing between them.
type RuleSet struct {
	Type           string             `json:"type"` // "remote" | "local"
	Tag            string             `json:"tag"`
	Format         string             `json:"format"`         // "binary" for .srs, "source" for .json
	URL            string             `json:"url,omitempty"`  // remote only
	Path           string             `json:"path,omitempty"` // local only
	HTTPClient     *RuleSetHTTPClient `json:"http_client,omitempty"`
	DownloadDetour string             `json:"download_detour,omitempty"`
	UpdateInterval string             `json:"update_interval,omitempty"`
}

// RuleSetHTTPClient configures how a remote rule-set is fetched.
//
// Detour must NOT be pointed at a bare `direct` outbound. Verified on 1.14.0:
// that combination is a startup FATAL --
// "detour to an empty direct outbound makes no sense" -- even though
// `sing-box check` accepts it. An unconfigured direct outbound is a no-op, so
// the engine treats detouring to it as an error.
//
// Leaving Detour empty and setting DomainResolver instead gives a clean start
// with no deprecation warning: the fetch uses the default dialer and resolves
// via the named DNS server. That is what BuildConfig emits.
type RuleSetHTTPClient struct {
	Detour string `json:"detour,omitempty"`
	// DomainResolver names a dns.servers[].tag used to resolve the rule-set
	// host. Required to avoid the 1.14 "implicit default HTTP client ... is
	// deprecated" warning.
	DomainResolver string `json:"domain_resolver,omitempty"`
}

// ExperimentalOptions carries the cache_file and clash_api blocks. Remote
// rule-sets work without cache_file, but then every engine restart re-downloads
// several hundred KB of .srs data -- on a metered or throttled link that is
// worth avoiding, and a failed download at startup delays the proxy coming up.
type ExperimentalOptions struct {
	CacheFile *CacheFileOptions `json:"cache_file,omitempty"`
	ClashAPI  *ClashAPIOptions  `json:"clash_api,omitempty"`
}

// CacheFileOptions is experimental.cache_file.
//
// Enabling this ALSO persists the selector's current pick across engine
// restarts. There is deliberately no store_selected field here: verified against
// 1.14.0, `store_selected` on cache_file is rejected outright as an unknown
// field, and the old clash_api.store_selected spelling parses but then FATALs
// with "cache_file and related fields in Clash API is deprecated in sing-box
// 1.8.0". Persistence is implicit in cache_file being on -- confirmed by pinning
// a selector member, restarting the engine, and reading it back unchanged.
//
// The practical consequence for this project: running clash_api WITHOUT a cache
// file means a pinned node silently reverts to the urltest group on every engine
// restart, so BuildConfig warns about that combination.
type CacheFileOptions struct {
	StoreFakeIP bool   `json:"store_fakeip,omitempty"`
	Enabled     bool   `json:"enabled"`
	Path        string `json:"path,omitempty"`
}

// ClashAPIOptions enables the Clash-compatible control API.
//
// This is the control channel for live selector changes. Switching the active
// node by regenerating config and calling Apply would drop every connection on
// the LAN and cost a few seconds of downtime; a PUT to the Clash API's
// /proxies/{group} switches between manual nodes in place with no restart.
// Auto/manual transitions rebuild the config to remove or restore URLTest.
//
// Requires a sing-box built with the with_clash_api tag (official releases are).
// The option block itself always parses, so a build without the tag accepts this
// config and simply never opens the listener -- which surfaces as a connection
// refused from the API layer, not as a config error.
type ClashAPIOptions struct {
	// ExternalController is the listen address, e.g. "127.0.0.1:9090". Keep it
	// on loopback: the API is unauthenticated unless Secret is set, and it can
	// switch outbounds and read traffic totals.
	ExternalController string `json:"external_controller,omitempty"`
	Secret             string `json:"secret,omitempty"`
	DefaultMode        string `json:"default_mode,omitempty"`
}

// RouteRule covers the subset of matchers and actions this package emits.
// `Action` is required by 1.11+; a rule with no action is a legacy route rule.
type RouteRule struct {
	Invert       bool     `json:"invert,omitempty"`
	SourceIPCIDR []string `json:"source_ip_cidr,omitempty"`
	Domain       []string `json:"domain,omitempty"`
	DomainSuffix []string `json:"domain_suffix,omitempty"`
	IPCIDR       []string `json:"ip_cidr,omitempty"`
	Inbound      []string `json:"inbound,omitempty"`
	Protocol     []string `json:"protocol,omitempty"`
	IPIsPrivate  bool     `json:"ip_is_private,omitempty"`
	Port         []int    `json:"port,omitempty"`
	// RuleSet references RuleSet.Tag values. Replaces the removed geoip/geosite
	// matchers.
	RuleSet []string `json:"rule_set,omitempty"`

	Action   string   `json:"action,omitempty"`
	Sniffer  []string `json:"sniffer,omitempty"`
	Timeout  string   `json:"timeout,omitempty"`
	Strategy string   `json:"strategy,omitempty"`
	Server   string   `json:"server,omitempty"`
	Outbound string   `json:"outbound,omitempty"`
	Method   string   `json:"method,omitempty"`
}

// --- outbounds --------------------------------------------------------------

type TLSOptions struct {
	Enabled    bool            `json:"enabled"`
	ServerName string          `json:"server_name,omitempty"`
	Insecure   bool            `json:"insecure,omitempty"`
	ALPN       []string        `json:"alpn,omitempty"`
	UTLS       *UTLSOptions    `json:"utls,omitempty"`
	Reality    *RealityOptions `json:"reality,omitempty"`
}

type UTLSOptions struct {
	Enabled     bool   `json:"enabled"`
	Fingerprint string `json:"fingerprint,omitempty"`
}

type RealityOptions struct {
	Enabled   bool   `json:"enabled"`
	PublicKey string `json:"public_key"`
	ShortID   string `json:"short_id,omitempty"`
}

type TransportOptions struct {
	Type        string              `json:"type"` // "ws" | "grpc" | "http"
	Path        string              `json:"path,omitempty"`
	Host        []string            `json:"host,omitempty"`
	Headers     map[string][]string `json:"headers,omitempty"`
	ServiceName string              `json:"service_name,omitempty"`
}

// VLESSOutbound / TrojanOutbound / VMessOutbound / ShadowsocksOutbound /
// Hysteria2Outbound mirror their documented schemas. RoutingMark is set from
// Options.RoutingMark so the engine's own egress can be excluded from
// interception if the nftables OUTPUT chain is ever tightened.
// Detour on each outbound is the multi-hop chain field: this outbound's
// connection to its OWN server is carried by the named outbound. Verified
// against the 1.14 dial-fields docs: when detour is set, every other dial field
// on that outbound is IGNORED -- including routing_mark. That is why
// BuildConfig refuses to emit both (see buildOutbound).
type VLESSOutbound struct {
	Type        string            `json:"type"`
	Tag         string            `json:"tag"`
	Server      string            `json:"server"`
	ServerPort  int               `json:"server_port"`
	UUID        string            `json:"uuid"`
	Flow        string            `json:"flow,omitempty"`
	TLS         *TLSOptions       `json:"tls,omitempty"`
	Transport   *TransportOptions `json:"transport,omitempty"`
	Detour      string            `json:"detour,omitempty"`
	RoutingMark int               `json:"routing_mark,omitempty"`
}

type TrojanOutbound struct {
	Type        string            `json:"type"`
	Tag         string            `json:"tag"`
	Server      string            `json:"server"`
	ServerPort  int               `json:"server_port"`
	Password    string            `json:"password"`
	TLS         *TLSOptions       `json:"tls,omitempty"`
	Transport   *TransportOptions `json:"transport,omitempty"`
	Detour      string            `json:"detour,omitempty"`
	RoutingMark int               `json:"routing_mark,omitempty"`
}

type VMessOutbound struct {
	Type        string            `json:"type"`
	Tag         string            `json:"tag"`
	Server      string            `json:"server"`
	ServerPort  int               `json:"server_port"`
	UUID        string            `json:"uuid"`
	Security    string            `json:"security,omitempty"`
	AlterID     int               `json:"alter_id,omitempty"`
	TLS         *TLSOptions       `json:"tls,omitempty"`
	Transport   *TransportOptions `json:"transport,omitempty"`
	Detour      string            `json:"detour,omitempty"`
	RoutingMark int               `json:"routing_mark,omitempty"`
}

type ShadowsocksOutbound struct {
	Type        string `json:"type"`
	Tag         string `json:"tag"`
	Server      string `json:"server"`
	ServerPort  int    `json:"server_port"`
	Method      string `json:"method"`
	Password    string `json:"password"`
	Detour      string `json:"detour,omitempty"`
	RoutingMark int    `json:"routing_mark,omitempty"`
}

type Hysteria2Outbound struct {
	Type        string      `json:"type"`
	Tag         string      `json:"tag"`
	Server      string      `json:"server"`
	ServerPort  int         `json:"server_port"`
	Password    string      `json:"password"`
	TLS         *TLSOptions `json:"tls,omitempty"`
	Detour      string      `json:"detour,omitempty"`
	RoutingMark int         `json:"routing_mark,omitempty"`
}

type DirectOutbound struct {
	Type string `json:"type"`
	Tag  string `json:"tag"`
	// DomainResolver names a dns.servers[].tag. Setting it also makes this
	// outbound "non-empty", which is required before anything can detour to it
	// on sing-box 1.14 (a bare direct outbound is rejected as a detour target).
	DomainResolver string `json:"domain_resolver,omitempty"`
	RoutingMark    int    `json:"routing_mark,omitempty"`
}

// DomainResolverOptions is route.default_domain_resolver. Required on 1.14:
// omitting it aborts startup with "missing `route.default_domain_resolver` or
// `domain_resolver` in dial fields is deprecated in sing-box 1.12.0 and will be
// removed in sing-box 1.14.0".
type DomainResolverOptions struct {
	Server   string `json:"server"`
	Strategy string `json:"strategy,omitempty"`
}

type SelectorOutbound struct {
	Type                      string   `json:"type"`
	Tag                       string   `json:"tag"`
	Outbounds                 []string `json:"outbounds"`
	Default                   string   `json:"default,omitempty"`
	InterruptExistConnections bool     `json:"interrupt_exist_connections,omitempty"`
}

// URLTestOutbound is the latency auto-switch group.
//
// Outbounds must be non-empty: verified against sing-box 1.14.0, an empty list
// is a hard startup failure ("initialize outbound: missing tags"), so
// BuildConfig omits the group entirely rather than emitting an empty one.
type URLTestOutbound struct {
	Type      string   `json:"type"`
	Tag       string   `json:"tag"`
	Outbounds []string `json:"outbounds"`
	URL       string   `json:"url,omitempty"`
	Interval  string   `json:"interval,omitempty"`
	// Tolerance in ms: a candidate must beat the current pick by more than this
	// to trigger a switch. Prevents flapping between two nodes a few ms apart.
	Tolerance                 int    `json:"tolerance,omitempty"`
	IdleTimeout               string `json:"idle_timeout,omitempty"`
	InterruptExistConnections bool   `json:"interrupt_exist_connections,omitempty"`
}
