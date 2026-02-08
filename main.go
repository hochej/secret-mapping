// secret-detector-export combines TruffleHog verification hosts and Gitleaks
// regex patterns into a unified secret detection dataset for Gondolin.
//
// From TruffleHog (AGPL-3.0): Only verification URLs/hosts are extracted
// (factual data, not copyrightable). No regex patterns are copied.
//
// From Gitleaks (MIT): Regex patterns, keywords, and metadata are extracted.
// MIT license allows free embedding with attribution.
//
// Each service gets a "keyword" derived from its name that can be used to
// match env var names (e.g., keyword "cloudflare" matches CLOUDFLARE_API_KEY).
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
)

func main() {
	thDir := flag.String("trufflehog", "", "Path to trufflehog/pkg/detectors/")
	glPath := flag.String("gitleaks", "", "Path to gitleaks/config/gitleaks.toml")
	outPath := flag.String("out", "-", "Output file path (or - for stdout)")
	flag.Parse()

	if *thDir == "" && *glPath == "" {
		exitErr(errors.New("at least one of -trufflehog or -gitleaks is required"))
	}

	var thDetectors []THDetector
	var glRules []GLRule

	if *thDir != "" {
		var skipped []string
		var err error
		thDetectors, skipped, err = extractTrufflehogDetectors(*thDir)
		if err != nil {
			exitErr(fmt.Errorf("trufflehog extraction: %w", err))
		}
		if len(skipped) > 0 {
			fmt.Fprintf(os.Stderr, "TruffleHog: skipped %d detectors\n", len(skipped))
		}
		fmt.Fprintf(os.Stderr, "TruffleHog: extracted %d detectors with hosts\n", len(thDetectors))
	}

	if *glPath != "" {
		var err error
		glRules, err = extractGitleaksRules(*glPath)
		if err != nil {
			exitErr(fmt.Errorf("gitleaks extraction: %w", err))
		}
		fmt.Fprintf(os.Stderr, "Gitleaks: extracted %d rules\n", len(glRules))
	}

	export := combine(thDetectors, glRules)

	var out *os.File
	if *outPath == "-" {
		out = os.Stdout
	} else {
		f, err := os.Create(*outPath)
		if err != nil {
			exitErr(fmt.Errorf("create output: %w", err))
		}
		defer f.Close()
		out = f
	}

	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")
	if err := enc.Encode(export); err != nil {
		exitErr(fmt.Errorf("encode json: %w", err))
	}

	// Print summary
	s := export.Stats
	fmt.Fprintf(os.Stderr, "\n=== Summary ===\n")
	fmt.Fprintf(os.Stderr, "Total services:       %d\n", s.TotalServices)
	fmt.Fprintf(os.Stderr, "  With hosts+rules:   %d (exact:%d prefix:%d alias:%d)\n",
		s.ServicesWithHosts, s.MatchExact, s.MatchPrefix, s.MatchAlias)
	fmt.Fprintf(os.Stderr, "  Rules only (no host):%d\n", s.ServicesNoHosts)
	fmt.Fprintf(os.Stderr, "  Hosts only (no rule):%d\n", s.THOnlyServices)
	fmt.Fprintf(os.Stderr, "Total GL rules:       %d (%d with hosts)\n", s.TotalRules, s.RulesWithHosts)
}

func exitErr(err error) {
	fmt.Fprintln(os.Stderr, "error:", err)
	os.Exit(1)
}
