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
	"path/filepath"
)

func main() {
	thDir := flag.String("trufflehog", "", "Path to trufflehog/pkg/detectors/")
	glPath := flag.String("gitleaks", "", "Path to gitleaks/config/gitleaks.toml")
	outPath := flag.String("out", "-", "Output file path (or - for stdout)")
	mode := flag.String("mode", "full", "Output mode: 'full' (all data) or 'gondolin' (slim, for pi-gondolin.ts)")
	force := flag.Bool("force", false, "Overwrite -out if it already exists")
	strict := flag.Bool("strict", false, "Treat TruffleHog URL/host extraction warnings as errors")
	allowIPHosts := flag.Bool("allow-ip-hosts", false, "Allow exporting IP-literal hosts (unsafe; default: false)")
	flag.Parse()

	if *mode != "full" && *mode != "gondolin" {
		exitErr(fmt.Errorf("invalid -mode %q: must be 'full' or 'gondolin'", *mode))
	}

	if *thDir == "" && *glPath == "" {
		exitErr(errors.New("at least one of -trufflehog or -gitleaks is required"))
	}

	var thDetectors []THDetector
	var glRules []GLRule

	if *thDir != "" {
		var skipped []string
		var warnings []error
		var err error
		thDetectors, skipped, warnings, err = extractTrufflehogDetectors(*thDir, THExtractOptions{AllowIPHosts: *allowIPHosts})
		if err != nil {
			exitErr(fmt.Errorf("trufflehog extraction: %w", err))
		}
		if len(skipped) > 0 {
			fmt.Fprintf(os.Stderr, "TruffleHog: skipped %d detectors\n", len(skipped))
		}
		if len(warnings) > 0 {
			fmt.Fprintf(os.Stderr, "TruffleHog: %d warnings (showing up to 5):\n", len(warnings))
			for i := 0; i < len(warnings) && i < 5; i++ {
				fmt.Fprintf(os.Stderr, "  - %v\n", warnings[i])
			}
			if *strict {
				exitErr(fmt.Errorf("trufflehog extraction produced %d warnings (first: %v)", len(warnings), warnings[0]))
			}
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

	// Choose output payload based on mode
	var output any
	switch *mode {
	case "gondolin":
		gondolin := toGondolinExport(export)
		output = gondolin
		fmt.Fprintf(os.Stderr, "\n=== Gondolin Export ===\n")
		fmt.Fprintf(os.Stderr, "Keyword→host mappings: %d\n", len(gondolin.KeywordHostMap))
		fmt.Fprintf(os.Stderr, "Exact-name mappings:   %d\n", len(gondolin.ExactNameHostMap))
		fmt.Fprintf(os.Stderr, "Value patterns:        %d (with host linkage: %d)\n",
			len(gondolin.ValuePatterns), countLinkedPatterns(gondolin.ValuePatterns))
	default:
		output = export
	}

	if *outPath == "-" {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(output); err != nil {
			exitErr(fmt.Errorf("encode json: %w", err))
		}
	} else {
		if err := writeJSONAtomic(*outPath, *force, output); err != nil {
			exitErr(err)
		}
	}

	// Print full summary (always useful on stderr)
	s := export.Stats
	fmt.Fprintf(os.Stderr, "\n=== Summary ===\n")
	fmt.Fprintf(os.Stderr, "Total services:       %d\n", s.TotalServices)
	fmt.Fprintf(os.Stderr, "  With hosts+rules:   %d (exact:%d prefix:%d alias:%d)\n",
		s.ServicesWithHosts, s.MatchExact, s.MatchPrefix, s.MatchAlias)
	fmt.Fprintf(os.Stderr, "  Rules only (no host):%d\n", s.ServicesNoHosts)
	fmt.Fprintf(os.Stderr, "  Hosts only (no rule):%d\n", s.THOnlyServices)
	fmt.Fprintf(os.Stderr, "Total GL rules:       %d (%d with hosts)\n", s.TotalRules, s.RulesWithHosts)
}

func writeJSONAtomic(outPath string, force bool, v any) error {
	if !force {
		if _, err := os.Stat(outPath); err == nil {
			return fmt.Errorf("output file already exists: %s (use -force to overwrite)", outPath)
		} else if !os.IsNotExist(err) {
			return fmt.Errorf("stat output: %w", err)
		}
	}

	dir := filepath.Dir(outPath)
	base := filepath.Base(outPath)
	f, err := os.CreateTemp(dir, base+".tmp-*")
	if err != nil {
		return fmt.Errorf("create temp output: %w", err)
	}
	tmpPath := f.Name()
	cleanup := func() { _ = os.Remove(tmpPath) }

	if err := f.Chmod(0o644); err != nil {
		_ = f.Close()
		cleanup()
		return fmt.Errorf("chmod temp output: %w", err)
	}

	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		_ = f.Close()
		cleanup()
		return fmt.Errorf("encode json: %w", err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		cleanup()
		return fmt.Errorf("sync temp output: %w", err)
	}
	if err := f.Close(); err != nil {
		cleanup()
		return fmt.Errorf("close temp output: %w", err)
	}

	// On Windows, Rename won't overwrite existing files.
	if force {
		_ = os.Remove(outPath)
	}

	if err := os.Rename(tmpPath, outPath); err != nil {
		cleanup()
		return fmt.Errorf("rename temp output: %w", err)
	}

	// Best-effort: sync the directory entry.
	if df, err := os.Open(dir); err == nil {
		_ = df.Sync()
		_ = df.Close()
	}

	return nil
}

func countLinkedPatterns(patterns []ValuePattern) int {
	n := 0
	for _, p := range patterns {
		if p.Keyword != "" {
			n++
		}
	}
	return n
}

func exitErr(err error) {
	fmt.Fprintln(os.Stderr, "error:", err)
	os.Exit(1)
}
