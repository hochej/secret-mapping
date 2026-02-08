package main

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// THDetector represents a single TruffleHog detector with extracted hosts.
type THDetector struct {
	DirName string   `json:"dir_name"` // original directory name
	Keyword string   `json:"keyword"`  // derived service keyword
	Hosts   []string `json:"hosts"`
}

type THExtractOptions struct {
	AllowIPHosts bool
}

// extractTrufflehogDetectors walks the TruffleHog detectors directory and
// extracts verification hosts from each detector's Go source files.
//
// IMPORTANT: Only URLs/hosts are extracted (factual data). No regex patterns
// are extracted to avoid AGPL license contamination.
func extractTrufflehogDetectors(detectorsRoot string, opts THExtractOptions) ([]THDetector, []string, []error, error) {
	entries, err := os.ReadDir(detectorsRoot)
	if err != nil {
		return nil, nil, nil, err
	}

	var detectors []THDetector
	var skipped []string
	var warnings []error

	for _, e := range entries {
		if !e.IsDir() {
			continue
		}

		dirName := e.Name()
		svcDir := filepath.Join(detectorsRoot, dirName)

		parseDir, err := chooseHighestVersionDir(svcDir)
		if err != nil {
			skipped = append(skipped, dirName+": "+err.Error())
			continue
		}

		hosts, ws, err := extractHostsFromGoPackage(parseDir, opts)
		warnings = append(warnings, ws...)
		if err != nil {
			skipped = append(skipped, dirName+": "+err.Error())
			continue
		}
		if len(hosts) == 0 {
			continue
		}

		sort.Strings(hosts)

		detectors = append(detectors, THDetector{
			DirName: dirName,
			Keyword: deriveKeywordFromTHName(dirName),
			Hosts:   hosts,
		})
	}

	sort.Slice(detectors, func(i, j int) bool {
		return detectors[i].DirName < detectors[j].DirName
	})
	sort.Strings(skipped)

	return detectors, skipped, warnings, nil
}

var versionDirRe = regexp.MustCompile(`^v(\d+)$`)

// chooseHighestVersionDir selects the highest versioned subdirectory if present.
// Many TruffleHog detectors are versioned as <service>/v1, <service>/v2, ...
func chooseHighestVersionDir(serviceDir string) (string, error) {
	entries, err := os.ReadDir(serviceDir)
	if err != nil {
		return "", err
	}

	bestVersion := -1
	bestDir := ""
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		m := versionDirRe.FindStringSubmatch(e.Name())
		if m == nil {
			continue
		}
		v, err := strconv.Atoi(m[1])
		if err != nil {
			continue
		}
		if v > bestVersion {
			bestVersion = v
			bestDir = filepath.Join(serviceDir, e.Name())
		}
	}

	if bestDir != "" {
		return bestDir, nil
	}
	return serviceDir, nil
}

// extractHostsFromGoPackage parses all non-test Go files and extracts hosts
// from http(s) URL string literals. Noise is filtered.
func extractHostsFromGoPackage(dir string, opts THExtractOptions) ([]string, []error, error) {
	fset := token.NewFileSet()

	pkgs, err := parser.ParseDir(fset, dir, func(fi os.FileInfo) bool {
		name := fi.Name()
		return strings.HasSuffix(name, ".go") && !strings.HasSuffix(name, "_test.go")
	}, 0)
	if err != nil {
		return nil, nil, err
	}

	seen := make(map[string]struct{})
	var hosts []string
	var warnings []error

	for _, pkg := range pkgs {
		for _, file := range pkg.Files {
			ast.Inspect(file, func(n ast.Node) bool {
				lit, ok := n.(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					return true
				}

				s, err := strconv.Unquote(lit.Value)
				if err != nil {
					warnings = append(warnings, fmt.Errorf("%s: unquote string literal %q: %w", fset.Position(lit.Pos()), lit.Value, err))
					return true
				}

				if !strings.HasPrefix(s, "https://") && !strings.HasPrefix(s, "http://") {
					return true
				}
				if isNoiseURL(s) {
					return true
				}

				pu, err := url.Parse(s)
				if err != nil {
					warnings = append(warnings, fmt.Errorf("%s: parse url %q: %w", fset.Position(lit.Pos()), s, err))
					return true
				}
				host := strings.ToLower(pu.Hostname())
				if host == "" || isNoiseHost(host, opts.AllowIPHosts) {
					return true
				}

				if _, ok := seen[host]; !ok {
					seen[host] = struct{}{}
					hosts = append(hosts, host)
				}

				return true
			})
		}
	}

	return hosts, warnings, nil
}

func isNoiseURL(u string) bool {
	lower := strings.ToLower(u)
	return strings.Contains(lower, "howtorotate.com") ||
		strings.Contains(lower, "github.com/truffle")
}

var validHostRe = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?)*$`)

func isNoiseHost(host string, allowIPHosts bool) bool {
	host = strings.ToLower(host)
	if host == "" {
		return true
	}
	if host == "localhost" {
		return true
	}
	if host == "howtorotate.com" || host == "github.com" || strings.HasSuffix(host, "fsf.org") {
		return true
	}

	// Safe default: no IP literals at all.
	if ip := net.ParseIP(host); ip != nil {
		if !allowIPHosts {
			return true
		}
		// Even with allowIPHosts, still block obvious non-routable ranges.
		if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() || ip.IsMulticast() {
			return true
		}
	}

	// Filter out internal-only namespaces.
	internalSuffixes := []string{
		".local", ".localdomain", ".internal", ".lan", ".home",
		".svc", ".cluster.local", ".svc.cluster.local",
	}
	for _, s := range internalSuffixes {
		if strings.HasSuffix(host, s) {
			return true
		}
	}

	// Filter out hostnames that aren't valid DNS names (e.g., regex fragments
	// like "(" from URLs embedded in regexp patterns)
	if !validHostRe.MatchString(host) {
		return true
	}
	// Must contain at least one dot (bare words aren't useful hosts)
	if !strings.Contains(host, ".") {
		return true
	}
	return false
}
