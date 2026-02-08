package main

import (
	"os"
	"sort"
	"strings"

	"github.com/BurntSushi/toml"
)

// GLRule represents a single Gitleaks rule with its derived service keyword.
type GLRule struct {
	ID          string   `json:"id"`
	Keyword     string   `json:"keyword"` // derived service keyword
	Description string   `json:"description,omitempty"`
	Regex       string   `json:"regex"`
	Entropy     float64  `json:"entropy,omitempty"`
	SecretGroup int      `json:"secret_group,omitempty"`
	Keywords    []string `json:"keywords,omitempty"`
}

// gitleaksConfig mirrors the TOML shape (only fields we care about).
type gitleaksConfig struct {
	Title      string         `toml:"title"`
	MinVersion string         `toml:"minVersion"`
	Rules      []gitleaksRule `toml:"rules"`
}

type gitleaksRule struct {
	ID          string   `toml:"id"`
	Description string   `toml:"description"`
	Regex       string   `toml:"regex"`
	Entropy     float64  `toml:"entropy"`
	SecretGroup int      `toml:"secretGroup"`
	Keywords    []string `toml:"keywords"`
	Tags        []string `toml:"tags"`
	SkipReport  bool     `toml:"skipReport"`
	Path        string   `toml:"path"`
}

// extractGitleaksRules reads gitleaks.toml and returns all rules with regex
// patterns, each annotated with a derived service keyword.
func extractGitleaksRules(tomlPath string) ([]GLRule, error) {
	data, err := os.ReadFile(tomlPath)
	if err != nil {
		return nil, err
	}

	var cfg gitleaksConfig
	if err := toml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}

	var rules []GLRule
	for _, r := range cfg.Rules {
		if r.SkipReport {
			continue // respect Gitleaks "skipReport" (typically noisy/informational rules)
		}
		if strings.TrimSpace(r.Regex) == "" {
			continue // skip path-only rules
		}

		rules = append(rules, GLRule{
			ID:          r.ID,
			Keyword:     deriveKeywordFromGitleaksID(r.ID),
			Description: r.Description,
			Regex:       r.Regex,
			Entropy:     r.Entropy,
			SecretGroup: r.SecretGroup,
			Keywords:    r.Keywords,
		})
	}

	sort.Slice(rules, func(i, j int) bool {
		if rules[i].Keyword == rules[j].Keyword {
			return rules[i].ID < rules[j].ID
		}
		return rules[i].Keyword < rules[j].Keyword
	})

	return rules, nil
}
