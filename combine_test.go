package main

import (
	"testing"
)

func TestCombineBasic(t *testing.T) {
	thDetectors := []THDetector{
		{DirName: "anthropic", Keyword: "anthropic", Hosts: []string{"api.anthropic.com"}},
		{DirName: "openai", Keyword: "openai", Hosts: []string{"api.openai.com"}},
		{DirName: "cloudflareapitoken", Keyword: "cloudflare", Hosts: []string{"api.cloudflare.com"}},
		{DirName: "nogl", Keyword: "nogl", Hosts: []string{"api.nogl.com"}}, // no GL match
	}

	glRules := []GLRule{
		{ID: "anthropic-api-key", Keyword: "anthropic", Regex: `sk-ant-api03-.*`},
		{ID: "openai-api-key", Keyword: "openai", Regex: `sk-[a-zA-Z0-9]{48}`},
		{ID: "cloudflare-api-key", Keyword: "cloudflare", Regex: `[a-f0-9]{37}`},
		{ID: "noth-secret", Keyword: "noth", Regex: `noth-[a-z]{10}`}, // no TH match
	}

	export := combine(thDetectors, glRules)

	// Check stats
	if export.Stats.ServicesWithHosts != 3 {
		t.Errorf("ServicesWithHosts = %d, want 3", export.Stats.ServicesWithHosts)
	}
	if export.Stats.ServicesNoHosts != 1 {
		t.Errorf("ServicesNoHosts = %d, want 1", export.Stats.ServicesNoHosts)
	}
	if export.Stats.THOnlyServices != 1 {
		t.Errorf("THOnlyServices = %d, want 1", export.Stats.THOnlyServices)
	}
	if export.Stats.TotalRules != 4 {
		t.Errorf("TotalRules = %d, want 4", export.Stats.TotalRules)
	}

	// Check that anthropic has hosts
	for _, svc := range export.Services {
		if svc.Keyword == "anthropic" {
			if len(svc.Hosts) == 0 {
				t.Error("anthropic should have hosts")
			}
			if svc.MatchType != "exact" {
				t.Errorf("anthropic match_type = %q, want 'exact'", svc.MatchType)
			}
			if len(svc.Rules) != 1 {
				t.Errorf("anthropic rules count = %d, want 1", len(svc.Rules))
			}
		}
		if svc.Keyword == "noth" {
			if len(svc.Hosts) != 0 {
				t.Error("noth should have no hosts")
			}
		}
	}

	// Check TH-only
	if len(export.THOnlyHosts) != 1 || export.THOnlyHosts[0].Keyword != "nogl" {
		t.Errorf("THOnlyHosts = %+v, want [{nogl ...}]", export.THOnlyHosts)
	}
}

func TestCombineAliasMatch(t *testing.T) {
	thDetectors := []THDetector{
		{DirName: "meraki", Keyword: "meraki", Hosts: []string{"api.meraki.com"}},
	}

	glRules := []GLRule{
		{ID: "cisco-meraki-api-key", Keyword: "cisco-meraki", Regex: `[a-f0-9]{40}`},
	}

	export := combine(thDetectors, glRules)

	if export.Stats.ServicesWithHosts != 1 {
		t.Errorf("ServicesWithHosts = %d, want 1", export.Stats.ServicesWithHosts)
	}
	if export.Stats.MatchAlias != 1 {
		t.Errorf("MatchAlias = %d, want 1", export.Stats.MatchAlias)
	}

	svc := export.Services[0]
	if svc.Keyword != "cisco-meraki" {
		t.Errorf("keyword = %q, want 'cisco-meraki'", svc.Keyword)
	}
	if len(svc.Hosts) == 0 || svc.Hosts[0] != "api.meraki.com" {
		t.Errorf("hosts = %v, want [api.meraki.com]", svc.Hosts)
	}
}

func TestCombinePrefixMatch(t *testing.T) {
	// This tests the case where TH keyword is a prefix-derived match
	// After suffix stripping, most matches are exact now, but prefix
	// matching is still useful as a fallback
	thDetectors := []THDetector{
		{DirName: "foobartoken", Keyword: "foobar", Hosts: []string{"api.foobar.com"}},
		{DirName: "foobarsecret", Keyword: "foobar", Hosts: []string{"auth.foobar.com"}},
	}

	glRules := []GLRule{
		{ID: "foobar-api-key", Keyword: "foobar", Regex: `fb-[a-z]{32}`},
	}

	export := combine(thDetectors, glRules)

	if export.Stats.ServicesWithHosts != 1 {
		t.Errorf("ServicesWithHosts = %d, want 1", export.Stats.ServicesWithHosts)
	}

	svc := export.Services[0]
	// Should have hosts from both TH detectors
	if len(svc.Hosts) != 2 {
		t.Errorf("hosts count = %d, want 2, got %v", len(svc.Hosts), svc.Hosts)
	}
}

func TestCombineMultipleRulesSameService(t *testing.T) {
	thDetectors := []THDetector{
		{DirName: "slack", Keyword: "slack", Hosts: []string{"slack.com", "api.slack.com"}},
	}

	glRules := []GLRule{
		{ID: "slack-bot-token", Keyword: "slack", Regex: `xoxb-.*`},
		{ID: "slack-user-token", Keyword: "slack", Regex: `xoxp-.*`},
		{ID: "slack-app-token", Keyword: "slack", Regex: `xapp-.*`},
	}

	export := combine(thDetectors, glRules)

	if export.Stats.ServicesWithHosts != 1 {
		t.Errorf("ServicesWithHosts = %d, want 1", export.Stats.ServicesWithHosts)
	}
	if export.Stats.TotalRules != 3 {
		t.Errorf("TotalRules = %d, want 3", export.Stats.TotalRules)
	}

	svc := export.Services[0]
	if len(svc.Rules) != 3 {
		t.Errorf("rules count = %d, want 3", len(svc.Rules))
	}
}

// TestCombineIntegration runs the full pipeline against real data if available.
func TestCombineIntegration(t *testing.T) {
	thRoot := "../../trufflehog/pkg/detectors"
	glPath := "../../gitleaks/config/gitleaks.toml"

	thDetectors, _, _, err := extractTrufflehogDetectors(thRoot, THExtractOptions{})
	if err != nil {
		t.Skip("TruffleHog detectors not found:", err)
	}
	glRules, err := extractGitleaksRules(glPath)
	if err != nil {
		t.Skip("Gitleaks config not found:", err)
	}

	export := combine(thDetectors, glRules)

	// Sanity checks on real data
	if export.Stats.TotalServices < 500 {
		t.Errorf("TotalServices = %d, expected >= 500", export.Stats.TotalServices)
	}
	if export.Stats.ServicesWithHosts < 70 {
		t.Errorf("ServicesWithHosts = %d, expected >= 70", export.Stats.ServicesWithHosts)
	}
	if export.Stats.TotalRules < 200 {
		t.Errorf("TotalRules = %d, expected >= 200", export.Stats.TotalRules)
	}
	if export.Stats.RulesWithHosts < 130 {
		t.Errorf("RulesWithHosts = %d, expected >= 130", export.Stats.RulesWithHosts)
	}

	// Check specific high-profile services have hosts
	mustHaveHosts := map[string]string{
		"anthropic":    "api.anthropic.com",
		"openai":       "api.openai.com",
		"github":       "api.github.com",
		"stripe":       "api.stripe.com",
		"cloudflare":   "api.cloudflare.com",
		"digitalocean": "api.digitalocean.com",
		"datadog":      "api.datadoghq.com",
		"slack":        "slack.com",
		"discord":      "discord.com",
		"sentry":       "sentry.io",
		"newrelic":     "api.newrelic.com",
	}

	svcMap := make(map[string]CombinedSvc)
	for _, svc := range export.Services {
		svcMap[svc.Keyword] = svc
	}

	for keyword, expectedHost := range mustHaveHosts {
		svc, ok := svcMap[keyword]
		if !ok {
			t.Errorf("missing service %q", keyword)
			continue
		}
		if len(svc.Hosts) == 0 {
			t.Errorf("service %q has no hosts", keyword)
			continue
		}
		found := false
		for _, h := range svc.Hosts {
			if h == expectedHost {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("service %q: expected host %q in %v", keyword, expectedHost, svc.Hosts)
		}
	}

	// Verify no garbage hosts (all must be valid DNS names with dots)
	for _, svc := range export.Services {
		for _, h := range svc.Hosts {
			if !validHostRe.MatchString(h) {
				t.Errorf("service %q has invalid host %q", svc.Keyword, h)
			}
		}
	}
	for _, th := range export.THOnlyHosts {
		for _, h := range th.Hosts {
			if !validHostRe.MatchString(h) {
				t.Errorf("TH-only %q has invalid host %q", th.Keyword, h)
			}
		}
	}

	// Verify all GL regex patterns compile
	for _, svc := range export.Services {
		for _, r := range svc.Rules {
			if r.Regex == "" {
				t.Errorf("service %q rule %q has empty regex", svc.Keyword, r.ID)
			}
			// Note: some Gitleaks patterns use features not in Go's regexp
			// (e.g., backreferences), so we don't test regexp.Compile here
		}
	}

	// Check no duplicate services
	seen := make(map[string]bool)
	for _, svc := range export.Services {
		if seen[svc.Keyword] {
			t.Errorf("duplicate service keyword %q", svc.Keyword)
		}
		seen[svc.Keyword] = true
	}
}

// TestTHKeywordDerivationCoverage checks that all TH detectors get
// reasonable keywords (not empty, not too short for major services).
func TestTHKeywordDerivationCoverage(t *testing.T) {
	thRoot := "../../trufflehog/pkg/detectors"
	thDetectors, _, _, err := extractTrufflehogDetectors(thRoot, THExtractOptions{})
	if err != nil {
		t.Skip("TruffleHog detectors not found:", err)
	}

	// Count how many unique keywords we get
	keywords := make(map[string][]string)
	for _, d := range thDetectors {
		if d.Keyword == "" {
			t.Errorf("empty keyword for dir %q", d.DirName)
			continue
		}
		keywords[d.Keyword] = append(keywords[d.Keyword], d.DirName)
	}

	t.Logf("TH detectors: %d, unique keywords: %d", len(thDetectors), len(keywords))

	// Keywords should consolidate detectors (fewer keywords than detectors)
	if len(keywords) >= len(thDetectors) {
		t.Errorf("keyword derivation didn't consolidate: %d keywords for %d detectors",
			len(keywords), len(thDetectors))
	}

	// Check some known consolidations
	for keyword, dirs := range keywords {
		if keyword == "cloudflare" && len(dirs) < 2 {
			t.Errorf("cloudflare should consolidate multiple dirs, got %v", dirs)
		}
		if keyword == "discord" && len(dirs) < 2 {
			t.Errorf("discord should consolidate multiple dirs, got %v", dirs)
		}
	}
}
