package main

import (
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
	URLs    []string `json:"urls,omitempty"`
}

// extractTrufflehogDetectors walks the TruffleHog detectors directory and
// extracts verification hosts from each detector's Go source files.
//
// IMPORTANT: Only URLs/hosts are extracted (factual data). No regex patterns
// are extracted to avoid AGPL license contamination.
func extractTrufflehogDetectors(detectorsRoot string) ([]THDetector, []string, error) {
	entries, err := os.ReadDir(detectorsRoot)
	if err != nil {
		return nil, nil, err
	}

	var detectors []THDetector
	var skipped []string

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

		urls, err := extractURLsFromGoPackage(parseDir)
		if err != nil {
			skipped = append(skipped, dirName+": "+err.Error())
			continue
		}

		hosts := deriveHostsFromURLs(urls)
		if len(hosts) == 0 {
			continue
		}

		sort.Strings(hosts)
		sort.Strings(urls)

		detectors = append(detectors, THDetector{
			DirName: dirName,
			Keyword: deriveKeywordFromTHName(dirName),
			Hosts:   hosts,
			URLs:    urls,
		})
	}

	sort.Slice(detectors, func(i, j int) bool {
		return detectors[i].DirName < detectors[j].DirName
	})
	sort.Strings(skipped)

	return detectors, skipped, nil
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

// extractURLsFromGoPackage parses all non-test Go files and extracts URL
// string literals. Only http(s) URLs are collected; noise is filtered.
func extractURLsFromGoPackage(dir string) ([]string, error) {
	fset := token.NewFileSet()

	pkgs, err := parser.ParseDir(fset, dir, func(fi os.FileInfo) bool {
		name := fi.Name()
		return strings.HasSuffix(name, ".go") && !strings.HasSuffix(name, "_test.go")
	}, parser.ParseComments)
	if err != nil {
		return nil, err
	}

	seen := map[string]bool{}
	var urls []string

	for _, pkg := range pkgs {
		for _, file := range pkg.Files {
			commentRanges := buildCommentRanges(fset, file)

			ast.Inspect(file, func(n ast.Node) bool {
				lit, ok := n.(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					return true
				}
				if inComment(fset, lit.Pos(), commentRanges) {
					return true
				}

				s, err := strconv.Unquote(lit.Value)
				if err != nil {
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
					return true
				}
				host := pu.Hostname()
				if host == "" || isNoiseHost(host) {
					return true
				}

				norm := pu.String()
				if !seen[norm] {
					seen[norm] = true
					urls = append(urls, norm)
				}
				return true
			})
		}
	}

	return urls, nil
}

type commentRange struct {
	start, end int
}

func buildCommentRanges(fset *token.FileSet, file *ast.File) []commentRange {
	ranges := make([]commentRange, 0, len(file.Comments))
	for _, cg := range file.Comments {
		if cg == nil {
			continue
		}
		ranges = append(ranges, commentRange{
			start: fset.Position(cg.Pos()).Offset,
			end:   fset.Position(cg.End()).Offset,
		})
	}
	return ranges
}

func inComment(fset *token.FileSet, pos token.Pos, ranges []commentRange) bool {
	off := fset.Position(pos).Offset
	for _, r := range ranges {
		if off >= r.start && off < r.end {
			return true
		}
	}
	return false
}

func deriveHostsFromURLs(urls []string) []string {
	seen := map[string]bool{}
	var hosts []string
	for _, raw := range urls {
		pu, err := url.Parse(raw)
		if err != nil {
			continue
		}
		h := strings.ToLower(pu.Hostname())
		if h != "" && !seen[h] {
			seen[h] = true
			hosts = append(hosts, h)
		}
	}
	return hosts
}

func isNoiseURL(u string) bool {
	lower := strings.ToLower(u)
	return strings.Contains(lower, "howtorotate.com") ||
		strings.Contains(lower, "github.com/truffle")
}

var validHostRe = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?)*$`)

func isNoiseHost(host string) bool {
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

	// Reject IP literals and common non-routable ranges to avoid propagating
	// potentially unsafe verification targets (SSRF in downstream users).
	if ip := net.ParseIP(host); ip != nil {
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
