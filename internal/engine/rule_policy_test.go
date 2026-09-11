package engine

import (
	"testing"
	"time"
)

func TestRulePolicyValidationAndOrder(t *testing.T) {
	p := DefaultRulePolicy()
	p.Rules = []UserRule{{Name: "override", Enabled: true, Match: "domain_suffix", Values: []string{"example.com"}, Action: "proxy"}}
	p.Sources = []RuleSource{{Tag: "custom-extra", URL: "https://example.com/extra.srs", Action: "reject", Enabled: true}}
	m := NewManager(Options{Logger: quietLogger()})
	if err := m.ConfigureRulePolicy(p, map[string]string{p.GeoIPURL: "/tmp/ip.srs", p.GeositeURL: "/tmp/site.srs", p.Sources[0].URL: "/tmp/extra.srs"}); err != nil {
		t.Fatal(err)
	}
	cfg, err := m.BuildConfig(testNodes())
	if err != nil {
		t.Fatal(err)
	}
	for _, rs := range cfg.Route.RuleSet {
		if rs.Type != "local" || rs.URL != "" || rs.Path == "" {
			t.Fatalf("not managed local: %+v", rs)
		}
	}
	custom, extra, iran := -1, -1, -1
	for i, r := range cfg.Route.Rules {
		if len(r.DomainSuffix) > 0 {
			custom = i
		}
		if len(r.RuleSet) > 0 {
			switch r.RuleSet[0] {
			case "custom-extra":
				extra = i
			case TagGeositeIR:
				iran = i
			}
		}
	}
	if custom < 4 || extra <= custom || iran <= extra {
		t.Fatalf("rule order custom=%d extra=%d iran=%d", custom, extra, iran)
	}
	invalid := CloneRulePolicy(p)
	invalid.Rules[0].Values = []string{"*.com"}
	if ValidateRulePolicy(invalid) == nil {
		t.Fatal("wildcard accepted")
	}
	invalid = CloneRulePolicy(p)
	invalid.Sources[0].URL = "file:///etc/passwd"
	if ValidateRulePolicy(invalid) == nil {
		t.Fatal("file source accepted")
	}
	invalid = CloneRulePolicy(p)
	invalid.Rules[0].Values[0] = "changed.example"
	if p.Rules[0].Values[0] != "example.com" {
		t.Fatal("policy aliases input")
	}
}
func TestCalendarSchedule(t *testing.T) {
	p := DefaultRulePolicy()
	p.Schedule = "weekly"
	p.Timezone = "Asia/Tehran"
	p.TimeOfDay = "03:00"
	p.Weekday = 5
	if err := ValidateRulePolicy(p); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 9, 10, 0, 0, 0, 0, time.UTC)
	got := NextRuleUpdate(p, time.Time{}, now)
	want := time.Date(2026, 9, 10, 23, 30, 0, 0, time.UTC)
	if !got.Equal(want) {
		t.Fatalf("got %v want %v", got, want)
	}
	next := NextRuleUpdate(p, got, got)
	if !next.Equal(want.AddDate(0, 0, 7)) {
		t.Fatalf("repeat %v", next)
	}
	p.Schedule = "interval"
	p.UpdateDays = 0
	if !NextRuleUpdate(p, got, now).IsZero() {
		t.Fatal("manual schedule enabled")
	}
	p.Schedule = "daily"
	p.Timezone = "invalid"
	if ValidateRulePolicy(p) == nil {
		t.Fatal("invalid timezone accepted")
	}
}
