package engine

// Iran bypass rule-sets.
//
// Domestic Iranian traffic must egress DIRECTLY, not through the proxy:
//   - Iranian services routinely block or degrade foreign IPs, so proxying them
//     makes them slower or outright broken.
//   - Sending domestic traffic abroad and back wastes the proxy's bandwidth,
//     which is usually the scarce resource.
//
// Sing-box 1.8 removed the `geoip` / `geosite` config sections and their
// route-rule matchers in favour of `rule_set`. These URLs were verified to
// return HTTP 200 with real payloads (geosite-ir.srs ~335 KB,
// geoip-ir.srs ~15 KB) at the time of writing.
//
// Format is "binary" because these are compiled .srs files. Passing "source"
// for a .srs is a startup failure, not a warning.
const (
	iranRuleSetBase = "https://raw.githubusercontent.com/Chocolate4U/Iran-sing-box-rules/rule-set/"

	TagGeositeIR      = "geosite-ir"
	TagGeoIPIR        = "geoip-ir"
	TagGeositeAdsIR   = "geosite-ads-ir"
	defaultRuleSetTTL = "7d"
)

// IranRuleSets returns the remote rule-set definitions.
//
// downloadDetour names the outbound used to FETCH the rule-sets. It must be an
// outbound that works before any rule-set is loaded -- normally "direct". Using
// a proxy outbound here is a bootstrap trap: the proxy may itself be
// unreachable until routing is up, and routing needs the rule-sets.
//
// blockAds adds the Iranian ads/tracker list. It is separate from the bypass
// lists because blocking is a different decision from routing, and a user who
// wants Iranian sites direct may not want ads dropped by the gateway (AdGuard
// Home already does that job on this host).
// resolverTag names the DNS server used to resolve the rule-set host; it must
// match a dns.servers[].tag in the generated config. legacyDetour selects the
// pre-1.14 download_detour spelling. See Options.LegacyDownloadDetour.
func IranRuleSets(downloadDetour, resolverTag string, blockAds, legacyDetour bool) []RuleSet {
	if downloadDetour == "" {
		downloadDetour = DefaultDirect
	}
	// Emit exactly one spelling. Verified on 1.14.0:
	//   http_client{domain_resolver}      -> clean start, no warning  (default)
	//   download_detour: "direct"         -> works, deprecation warning
	//   http_client{detour: "direct"}     -> startup FATAL, do not emit
	newSet := func(tag, file string) RuleSet {
		rs := RuleSet{
			Type:           "remote",
			Tag:            tag,
			Format:         "binary",
			URL:            iranRuleSetBase + file,
			UpdateInterval: defaultRuleSetTTL,
		}
		if legacyDetour {
			rs.DownloadDetour = downloadDetour
		} else {
			rs.HTTPClient = &RuleSetHTTPClient{DomainResolver: resolverTag}
		}
		return rs
	}
	sets := []RuleSet{
		newSet(TagGeositeIR, "geosite-ir.srs"),
		newSet(TagGeoIPIR, "geoip-ir.srs"),
	}
	if blockAds {
		sets = append(sets, newSet(TagGeositeAdsIR, "geosite-category-ads-all.srs"))
	}
	return sets
}

// iranRules returns the route rules that act on the sets above.
//
// Ordering matters and is not arbitrary: sing-box evaluates rules top-down and
// stops at the first match. The ads reject must precede the direct bypass,
// because an Iranian ad domain appears in BOTH lists and whichever rule comes
// first wins.
func iranRules(blockAds bool) []RouteRule {
	var rules []RouteRule
	if blockAds {
		rules = append(rules, RouteRule{
			RuleSet: []string{TagGeositeAdsIR},
			Action:  "reject",
		})
	}
	// Domain-based bypass. Matched on the sniffed domain, which is why the
	// sniff rule must run before this one.
	rules = append(rules, RouteRule{
		RuleSet:  []string{TagGeositeIR},
		Action:   "route",
		Outbound: DefaultDirect,
	})
	// IP-based bypass, for connections to Iranian IPs with no usable domain
	// (direct-to-IP, failed sniff, non-HTTP protocols).
	rules = append(rules, RouteRule{
		RuleSet:  []string{TagGeoIPIR},
		Action:   "route",
		Outbound: DefaultDirect,
	})
	return rules
}
