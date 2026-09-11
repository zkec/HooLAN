package engine

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
	_ "time/tzdata"
)

// RulePolicy is the operator-editable subset of routing, not arbitrary sing-box JSON.
type RulePolicy struct {
	Schedule   string       `json:"schedule,omitempty"` // interval, daily, weekly
	TimeOfDay  string       `json:"time_of_day,omitempty"`
	Weekday    int          `json:"weekday"` // Sunday=0
	Timezone   string       `json:"timezone,omitempty"`
	Sources    []RuleSource `json:"sources"`
	UpdateDays int          `json:"update_days"` // 0 means manual updates only
	GeoIPURL   string       `json:"geoip_url"`
	GeositeURL string       `json:"geosite_url"`
	IranAction string       `json:"iran_action"`
	Rules      []UserRule   `json:"rules"`
}
type RuleSource struct {
	Tag     string `json:"tag"`
	URL     string `json:"url"`
	Action  string `json:"action"`
	Enabled bool   `json:"enabled"`
}
type UserRule struct {
	Name    string   `json:"name"`
	Enabled bool     `json:"enabled"`
	Match   string   `json:"match"`
	Values  []string `json:"values"`
	Action  string   `json:"action"`
}

func DefaultRulePolicy() RulePolicy {
	return RulePolicy{UpdateDays: 7, GeoIPURL: iranRuleSetBase + "geoip-ir.srs", GeositeURL: iranRuleSetBase + "geosite-ir.srs", IranAction: "direct", Rules: []UserRule{}}
}
func CloneRulePolicy(p RulePolicy) RulePolicy {
	p.Sources = append([]RuleSource{}, p.Sources...)
	p.Rules = append([]UserRule{}, p.Rules...)
	for i := range p.Rules {
		p.Rules[i].Values = append([]string{}, p.Rules[i].Values...)
	}
	return p
}
func ValidateRulePolicy(p RulePolicy) error {
	if p.Schedule != "" && p.Schedule != "interval" && p.Schedule != "daily" && p.Schedule != "weekly" {
		return fmt.Errorf("invalid schedule")
	}
	if p.Schedule == "daily" || p.Schedule == "weekly" {
		if _, err := time.Parse("15:04", p.TimeOfDay); err != nil {
			return fmt.Errorf("time must be HH:MM")
		}
		if p.Weekday < 0 || p.Weekday > 6 {
			return fmt.Errorf("invalid weekday")
		}
		if _, err := time.LoadLocation(p.Timezone); err != nil || p.Timezone == "" {
			return fmt.Errorf("invalid IANA timezone")
		}
	}
	if len(p.Sources) > 20 {
		return fmt.Errorf("at most 20 additional rule sets")
	}
	seen := map[string]bool{}
	for _, src := range p.Sources {
		if !strings.HasPrefix(src.Tag, "custom-") || len(src.Tag) > 80 || seen[src.Tag] {
			return fmt.Errorf("unique source tag must start with custom-")
		}
		seen[src.Tag] = true
		for _, c := range src.Tag {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return fmt.Errorf("source tags use lowercase letters, digits, hyphens")
			}
		}
		if src.Action != "direct" && src.Action != "proxy" && src.Action != "reject" {
			return fmt.Errorf("invalid source action")
		}
	}

	if p.UpdateDays < 0 || p.UpdateDays > 365 {
		return fmt.Errorf("update days must be 0 (manual) or 1–365")
	}
	for _, raw := range p.SourceURLs() {
		u, err := url.Parse(raw)
		if err != nil || len(raw) > 4096 || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Fragment != "" {
			return fmt.Errorf("rule-set sources must be HTTPS URLs without credentials or fragments")
		}
	}
	validAction := func(a string) bool { return a == "direct" || a == "proxy" || a == "reject" }
	if !validAction(p.IranAction) {
		return fmt.Errorf("invalid Iran action")
	}
	if len(p.Rules) > 100 {
		return fmt.Errorf("at most 100 custom rules are supported")
	}
	for _, r := range p.Rules {
		if strings.TrimSpace(r.Name) == "" || len(r.Name) > 100 || !validAction(r.Action) {
			return fmt.Errorf("each rule needs a name (up to 100 characters) and a valid action")
		}
		if r.Match != "domain" && r.Match != "domain_suffix" && r.Match != "ip_cidr" {
			return fmt.Errorf("invalid match type for %s", r.Name)
		}
		if len(r.Values) == 0 || len(r.Values) > 100 {
			return fmt.Errorf("rule %s needs 1–100 match values", r.Name)
		}
		for _, v := range r.Values {
			if r.Match == "ip_cidr" {
				if _, err := netip.ParsePrefix(v); err != nil {
					return fmt.Errorf("invalid CIDR %q", v)
				}
				continue
			}
			if len(v) == 0 || len(v) > 253 || strings.Trim(v, ".") != v || strings.ContainsAny(v, " /:\\*\t\r\n") {
				return fmt.Errorf("invalid domain %q", v)
			}
			for _, label := range strings.Split(v, ".") {
				if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
					return fmt.Errorf("invalid domain %q", v)
				}
				for _, c := range label {
					if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
						return fmt.Errorf("use ASCII/punycode domains: %q", v)
					}
				}
			}
		}
	}
	return nil
}
func (m *Manager) ConfigureRulePolicy(p RulePolicy, files map[string]string) error {
	if err := ValidateRulePolicy(p); err != nil {
		return err
	}
	m.settingsMu.Lock()
	defer m.settingsMu.Unlock()
	p = CloneRulePolicy(p)
	m.rulePolicy = &p
	m.ruleFiles = make(map[string]string, len(files))
	for u, path := range files {
		m.ruleFiles[u] = path
	}
	return nil
}
func actionRule(action string) RouteRule {
	if action == "reject" {
		return RouteRule{Action: "reject"}
	}
	return RouteRule{Action: "route", Outbound: action}
}

// Called under settingsMu by BuildConfig. Safety, sniff, DNS and private rules
// remain first; custom rules precede the editable Iran rules.
func (m *Manager) applyRulePolicy(route *RouteOptions) {
	if m.rulePolicy == nil {
		return
	}
	p := m.rulePolicy
	for i := range route.RuleSet {
		rs := &route.RuleSet[i]
		switch rs.Tag {
		case TagGeoIPIR:
			rs.URL = p.GeoIPURL
		case TagGeositeIR:
			rs.URL = p.GeositeURL
		default:
			continue
		}
		if path := m.ruleFiles[rs.URL]; path != "" {
			*rs = RuleSet{Type: "local", Tag: rs.Tag, Format: "binary", Path: path}
		} else {
			// Managed sources are updated by the Go scheduler, including while OFF.
			// Before the first managed download, retain remote bootstrap availability.
			rs.UpdateInterval = "876000h" // only Go schedules refreshes after bootstrap
		}
	}
	var base, iran []RouteRule
	for _, r := range route.Rules {
		if len(r.RuleSet) > 0 && (r.RuleSet[0] == TagGeositeIR || r.RuleSet[0] == TagGeoIPIR) {
			rr := actionRule(p.IranAction)
			rr.RuleSet = r.RuleSet
			iran = append(iran, rr)
		} else {
			base = append(base, r)
		}
	}
	for _, u := range p.Rules {
		if !u.Enabled {
			continue
		}
		r := actionRule(u.Action)
		switch u.Match {
		case "domain":
			r.Domain = u.Values
		case "domain_suffix":
			r.DomainSuffix = u.Values
		case "ip_cidr":
			r.IPCIDR = u.Values
		}
		base = append(base, r)
	}
	for _, src := range p.Sources {
		if !src.Enabled {
			continue
		}
		rs := RuleSet{Type: "remote", Tag: src.Tag, Format: "binary", URL: src.URL, HTTPClient: &RuleSetHTTPClient{DomainResolver: DefaultResolverTag}, UpdateInterval: "876000h"}
		if path := m.ruleFiles[src.URL]; path != "" {
			rs = RuleSet{Type: "local", Tag: src.Tag, Format: "binary", Path: path}
		}
		route.RuleSet = append(route.RuleSet, rs)
		r := actionRule(src.Action)
		r.RuleSet = []string{src.Tag}
		base = append(base, r)
	}
	route.Rules = append(base, iran...)
}

// FetchRuleSets stages and validates BOTH downloads before publishing a new
// immutable generation. Existing live files and sing-box's cache are untouched.
func (m *Manager) FetchRuleSets(ctx context.Context, p RulePolicy) (map[string]string, error) {
	if err := ValidateRulePolicy(p); err != nil {
		return nil, err
	}
	dir := filepath.Join(filepath.Dir(m.opts.ConfigPath), "rule-sets")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	stage, err := os.MkdirTemp(dir, ".download-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(stage)
	client := &http.Client{Timeout: 45 * time.Second, CheckRedirect: func(r *http.Request, via []*http.Request) error {
		if len(via) >= 5 || r.URL.Scheme != "https" {
			return fmt.Errorf("invalid rule-set redirect")
		}
		return nil
	}}
	files := map[string]string{}
	for _, raw := range p.SourceURLs() {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, raw, nil)
		if err != nil {
			return nil, err
		}
		res, err := client.Do(req)
		if err != nil {
			return nil, fmt.Errorf("download rule-set: %w", err)
		}
		data, readErr := io.ReadAll(io.LimitReader(res.Body, 16*1024*1024+1))
		res.Body.Close()
		if res.StatusCode != 200 || readErr != nil || len(data) > 16*1024*1024 || len(data) < 4 {
			return nil, fmt.Errorf("invalid rule-set download (HTTP %d, size %d): %v", res.StatusCode, len(data), readErr)
		}
		name := fmt.Sprintf("%x.srs", sha256.Sum256([]byte(raw)))
		path := filepath.Join(stage, name)
		if err := os.WriteFile(path, data, 0600); err != nil {
			return nil, err
		}
		// Decompile validates the compressed SRS payload, not just its magic bytes.
		cmd := exec.CommandContext(ctx, m.opts.BinaryPath, "rule-set", "decompile", "--output", os.DevNull, path)
		if err := cmd.Run(); err != nil {
			return nil, fmt.Errorf("rule-set validation failed: %w", err)
		}
		files[raw] = name
	}
	final := filepath.Join(dir, fmt.Sprintf("generation-%d", time.Now().UnixNano()))
	if err := os.Rename(stage, final); err != nil {
		return nil, err
	}
	for u, name := range files {
		files[u] = filepath.Join(final, name)
	}
	return files, nil
}

// SourceURLs includes disabled sources so they can be prepared while routing is off.
func (p RulePolicy) SourceURLs() []string {
	urls := []string{p.GeoIPURL, p.GeositeURL}
	seen := map[string]bool{p.GeoIPURL: true, p.GeositeURL: true}
	for _, s := range p.Sources {
		if !seen[s.URL] {
			urls = append(urls, s.URL)
			seen[s.URL] = true
		}
	}
	return urls
}

// NextRuleUpdate computes a wall-clock schedule in the configured timezone.
func NextRuleUpdate(p RulePolicy, last, now time.Time) time.Time {
	if p.Schedule != "daily" && p.Schedule != "weekly" {
		if p.UpdateDays == 0 {
			return time.Time{}
		}
		return last.Add(time.Duration(p.UpdateDays) * 24 * time.Hour)
	}
	loc, err := time.LoadLocation(p.Timezone)
	if err != nil {
		return time.Time{}
	}
	clock, err := time.Parse("15:04", p.TimeOfDay)
	if err != nil {
		return time.Time{}
	}
	anchor := last
	if anchor.IsZero() {
		anchor = now
	}
	local := anchor.In(loc)
	for day := 0; day < 9; day++ {
		date := local.AddDate(0, 0, day)
		candidate := time.Date(date.Year(), date.Month(), date.Day(), clock.Hour(), clock.Minute(), 0, 0, loc)
		if p.Schedule == "weekly" && int(candidate.Weekday()) != p.Weekday {
			continue
		}
		if candidate.After(anchor) {
			return candidate
		}
	}
	return time.Time{}
}
