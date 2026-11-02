package tools

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	"pentagi/pkg/config"

	"github.com/sirupsen/logrus"
)

const (
	vulnScanFindingsDir       = "/opt/assessment/findings"
	maxVulnScanResultSize     = 80 * 1024 // 80KB hard cap on formatted report
	maxFindingEvidenceSize    = 2048      // per-finding evidence excerpt cap
	vulnScanHardRateLimit     = 100       // nuclei -rl hard ceiling
	vulnScanMaxTimeout        = 10800     // 3 hours, matches terminal max
	defaultVulnScanExtraSecs  = 10        // subtracted from timeout for shell 'timeout'
)

// vulnScanFinding is the unified internal representation of a scanner finding.
type vulnScanFinding struct {
	Severity   string   `json:"severity"`
	Title      string   `json:"title"`
	CVE        string   `json:"cve,omitempty"`
	CVSS       float64  `json:"cvss,omitempty"`
	CWE        string   `json:"cwe,omitempty"`
	URL        string   `json:"url,omitempty"`
	Target     string   `json:"target,omitempty"`
	Template   string   `json:"template,omitempty"`
	Confidence string   `json:"confidence"`
	Evidence   string   `json:"evidence"`
	References []string `json:"references,omitempty"`
}

type vulnscan struct {
	term       *terminal
	cfg        *config.Config
	rateLimit  int
	timeout    time.Duration
	allowLocal bool
}

func NewVulnScanTool(
	term *terminal,
	cfg *config.Config,
	defaultRateLimit int,
	defaultTimeout time.Duration,
) Tool {
	return &vulnscan{
		term:       term,
		cfg:        cfg,
		rateLimit:  defaultRateLimit,
		timeout:    defaultTimeout,
		allowLocal: cfg.VulnScanAllowLocal,
	}
}

func (v *vulnscan) IsAvailable() bool {
	if v == nil || v.term == nil {
		return false
	}
	if v.cfg == nil || !v.cfg.VulnScanEnabled {
		return false
	}
	return v.term.IsAvailable()
}

func (v *vulnscan) Handle(ctx context.Context, name string, args json.RawMessage) (string, error) {
	if !v.IsAvailable() {
		return "", fmt.Errorf("vulnscan is not available")
	}

	logger := logrus.WithContext(ctx).WithFields(enrichLogrusFields(v.term.flowID, v.term.taskID, v.term.subtaskID, logrus.Fields{
		"tool": name,
		"args": string(args),
	}))

	var action VulnScanAction
	if err := json.Unmarshal(args, &action); err != nil {
		logger.WithError(err).Error("failed to unmarshal vulnscan action")
		return "", fmt.Errorf("failed to unmarshal vulnscan action: %w", err)
	}

	if err := v.validateTarget(action.Target); err != nil {
		logger.WithError(err).Error("target validation failed")
		return "", fmt.Errorf("target validation failed: %w", err)
	}

	timeout := v.normalizeTimeout(action.Timeout)
	shellTimeoutSecs := int(timeout.Seconds()) - defaultVulnScanExtraSecs
	if shellTimeoutSecs < 10 {
		shellTimeoutSecs = 10
	}

	outFile := v.buildOutFilePath(string(action.Scanner))

	cmd, err := v.buildScanCommand(action, outFile, shellTimeoutSecs)
	if err != nil {
		logger.WithError(err).Error("failed to build scan command")
		return "", fmt.Errorf("failed to build scan command: %w", err)
	}

	logger = logger.WithFields(logrus.Fields{
		"scanner":   action.Scanner,
		"target":    action.Target,
		"out_file":  outFile,
		"timeout":   timeout,
		"detach":    action.Detach.Bool(),
	})

	// Ensure findings directory exists inside the container
	mkdirCmd := fmt.Sprintf("mkdir -p %s", vulnScanFindingsDir)
	if _, err := v.term.ExecCommand(ctx, "", mkdirCmd, false, 30*time.Second); err != nil {
		logger.WithError(err).Warn("failed to create findings directory, continuing anyway")
	}

	if action.Detach.Bool() {
		_, err := v.term.ExecCommand(ctx, "", cmd, true, timeout)
		if err != nil {
			return v.term.wrapCommandResult(ctx, args, name,
				fmt.Sprintf("Background scan failed to start: %v", err), err)
		}
		return v.term.wrapCommandResult(ctx, args, name,
			fmt.Sprintf("Scan started in background. Results will be written to %s. "+
				"Use the file tool to read this file once the scan completes.", outFile), nil)
	}

	// Blocking scan
	_, err = v.term.ExecCommand(ctx, "", cmd, false, timeout)
	if err != nil {
		// Even on error, try to read partial results
		logger.WithError(err).Warn("scan command returned error, attempting to read partial results")
	}

	rawFile, readErr := v.term.readFileFromContainer(ctx, v.term.flowID, outFile)
	if readErr != nil {
		if err != nil {
			return v.term.wrapCommandResult(ctx, args, name,
				fmt.Sprintf("Scan failed: %v and results file could not be read: %v", err, readErr), err)
		}
		return v.term.wrapCommandResult(ctx, args, name,
			fmt.Sprintf("Scan completed but results file could not be read: %v", readErr), readErr)
	}

	if strings.TrimSpace(rawFile) == "" {
		return v.term.wrapCommandResult(ctx, args, name,
			"Scan completed successfully. No findings detected.", nil)
	}

	findings := parseScannerOutput(string(action.Scanner), rawFile)
	findings = applySeverityFilter(findings, string(action.Severity))
	findings = capResults(findings, v.cfg.VulnScanMaxResults)

	report := formatVulnScanResults(action, findings, cmd)
	return v.term.wrapCommandResult(ctx, args, name, report, nil)
}

func (v *vulnscan) normalizeTimeout(actionTimeout Int64) time.Duration {
	if actionTimeout > 0 && int64(actionTimeout) <= vulnScanMaxTimeout {
		return time.Duration(actionTimeout) * time.Second
	}
	if v.timeout > 0 && v.timeout <= time.Duration(vulnScanMaxTimeout)*time.Second {
		return v.timeout
	}
	return 30 * time.Minute
}

func (v *vulnscan) validateTarget(target string) error {
	if strings.TrimSpace(target) == "" {
		return fmt.Errorf("target cannot be empty")
	}

	parsed := strings.TrimSpace(target)

	// If it's a URL, extract host
	host := parsed
	if strings.HasPrefix(parsed, "http://") || strings.HasPrefix(parsed, "https://") {
		u, err := url.Parse(parsed)
		if err != nil {
			return fmt.Errorf("invalid URL: %w", err)
		}
		host = u.Hostname()
	} else {
		// Strip port if present
		if h, _, err := net.SplitHostPort(parsed); err == nil {
			host = h
		}
	}

	if host == "" {
		return fmt.Errorf("could not extract host from target")
	}

	// Check for loopback / link-local unless explicitly allowed
	if !v.allowLocal {
		ip := net.ParseIP(host)
		if ip != nil {
			if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsPrivate() {
				return fmt.Errorf("target resolves to a private/loopback address; set VULNSCAN_ALLOW_LOCAL=true to allow")
			}
		}
	}

	return nil
}

func (v *vulnscan) buildOutFilePath(scanner string) string {
	return fmt.Sprintf("%s/vulnscan_%s_%d.%s",
		vulnScanFindingsDir, scanner, time.Now().Unix(), scannerOutputExt(scanner))
}

func scannerOutputExt(scanner string) string {
	switch scanner {
	case "nuclei":
		return "jsonl"
	case "nikto":
		return "json"
	case "sslscan":
		return "xml"
	default:
		return "txt"
	}
}

func (v *vulnscan) buildScanCommand(action VulnScanAction, outFile string, shellTimeoutSecs int) (string, error) {
	switch action.Scanner {
	case "nuclei":
		return v.buildNucleiCommand(action, outFile, shellTimeoutSecs), nil
	case "nikto":
		return v.buildNiktoCommand(action, outFile, shellTimeoutSecs), nil
	case "sslscan":
		return v.buildSslscanCommand(action, outFile, shellTimeoutSecs), nil
	default:
		return "", fmt.Errorf("unknown scanner: %s", action.Scanner)
	}
}

func (v *vulnscan) resolveRateLimit(actionRate Int64) int {
	rl := v.rateLimit
	if actionRate > 0 {
		rl = int(actionRate)
	}
	if rl > vulnScanHardRateLimit {
		rl = vulnScanHardRateLimit
	}
	if rl <= 0 {
		rl = 50
	}
	return rl
}

func (v *vulnscan) buildNucleiCommand(action VulnScanAction, outFile string, timeoutSecs int) string {
	rl := v.resolveRateLimit(action.RateLimit)

	var parts []string
	parts = append(parts, fmt.Sprintf("timeout %d nuclei", timeoutSecs))
	parts = append(parts, "-u", action.Target)

	if action.Ports != "" {
		parts = append(parts, "-p", action.Ports)
	}
	if action.Severity != "" {
		parts = append(parts, "-severity", string(action.Severity))
	}
	if len(action.Tags) > 0 {
		parts = append(parts, "-tags", strings.Join([]string(action.Tags), ","))
	}

	parts = append(parts,
		"-rl", fmt.Sprintf("%d", rl),
		"-c", "15",
		"-silent",
		"-jsonl",
		"-o", outFile,
		"-nc",
	)

	return strings.Join(parts, " ")
}

func (v *vulnscan) buildNiktoCommand(action VulnScanAction, outFile string, timeoutSecs int) string {
	var parts []string
	parts = append(parts, fmt.Sprintf("timeout %d nikto", timeoutSecs))
	parts = append(parts, "-h", action.Target)

	if action.Ports != "" {
		parts = append(parts, "-p", action.Ports)
	}

	parts = append(parts,
		"-Format", "json",
		"-o", outFile,
		"-Tuning", "123b",
		"-nointeractive",
	)

	return strings.Join(parts, " ")
}

func (v *vulnscan) buildSslscanCommand(action VulnScanAction, outFile string, timeoutSecs int) string {
	return fmt.Sprintf("timeout %d sslscan --xml=%s %s", timeoutSecs, outFile, action.Target)
}

// ---------- Output parsers ----------

func parseScannerOutput(scanner, raw string) []vulnScanFinding {
	switch scanner {
	case "nuclei":
		return parseNucleiOutput(raw)
	case "nikto":
		return parseNiktoOutput(raw)
	case "sslscan":
		return parseSslscanOutput(raw)
	default:
		return nil
	}
}

func parseNucleiOutput(raw string) []vulnScanFinding {
	var findings []vulnScanFinding

	lines := strings.Split(strings.TrimSpace(raw), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		var obj map[string]any
		if err := json.Unmarshal([]byte(line), &obj); err != nil {
			continue
		}

		finding := vulnScanFinding{
			Confidence: "confirmed",
		}

		if v, ok := obj["template-id"].(string); ok {
			finding.Template = v
		}
		if v, ok := obj["templateID"].(string); ok && finding.Template == "" {
			finding.Template = v
		}

		if info, ok := obj["info"].(map[string]any); ok {
			if v, ok := info["name"].(string); ok {
				finding.Title = v
			}
			if v, ok := info["severity"].(string); ok {
				finding.Severity = normalizeSeverity(v)
			}
			if class, ok := info["classification"].(map[string]any); ok {
				if cves, ok := class["cve-id"].([]any); ok && len(cves) > 0 {
					if c, ok := cves[0].(string); ok {
						finding.CVE = c
					}
				} else if c, ok := class["cve-id"].(string); ok {
					finding.CVE = c
				}
				if cvss, ok := class["cvss-score"].(float64); ok {
					finding.CVSS = cvss
				}
				if cwes, ok := class["cwe-id"].([]any); ok && len(cwes) > 0 {
					if c, ok := cwes[0].(string); ok {
						finding.CWE = c
					}
				} else if c, ok := class["cwe-id"].(string); ok {
					finding.CWE = c
				}
			}
			if refs, ok := info["reference"].([]any); ok {
				for _, r := range refs {
					if s, ok := r.(string); ok {
						finding.References = append(finding.References, s)
					}
				}
			}
		}

		if v, ok := obj["matched-at"].(string); ok {
			finding.URL = v
		}
		if v, ok := obj["host"].(string); ok {
			finding.Target = v
		}

		// Build evidence from the raw line (truncated)
		finding.Evidence = truncateString(line, maxFindingEvidenceSize)

		if finding.Severity == "" {
			finding.Severity = "info"
		}
		if finding.Title == "" {
			finding.Title = finding.Template
		}

		findings = append(findings, finding)
	}

	return findings
}

func parseNiktoOutput(raw string) []vulnScanFinding {
	var findings []vulnScanFinding

	// nikto -Format json outputs a single JSON object
	var obj map[string]any
	if err := json.Unmarshal([]byte(raw), &obj); err != nil {
		// Maybe it's an array
		var arr []map[string]any
		if err2 := json.Unmarshal([]byte(raw), &arr); err2 != nil {
			return nil
		}
		for _, item := range arr {
			findings = append(findings, niktoItemToFinding(item))
		}
		return findings
	}

	// Single object — may contain "vulnerabilities" array
	if vulns, ok := obj["vulnerabilities"].([]any); ok {
		for _, v := range vulns {
			if item, ok := v.(map[string]any); ok {
				findings = append(findings, niktoItemToFinding(item))
			}
		}
	}
	// Also check top-level for items (some nikto versions)
	if items, ok := obj["items"].([]any); ok {
		for _, v := range items {
			if item, ok := v.(map[string]any); ok {
				findings = append(findings, niktoItemToFinding(item))
			}
		}
	}

	return findings
}

func niktoItemToFinding(item map[string]any) vulnScanFinding {
	finding := vulnScanFinding{
		Severity:   "medium",
		Confidence: "likely",
	}

	if v, ok := item["msg"].(string); ok {
		finding.Title = v
		finding.Evidence = truncateString(v, maxFindingEvidenceSize)
	}
	if v, ok := item["id"].(string); ok {
		finding.Template = v
	}
	if v, ok := item["url"].(string); ok {
		finding.URL = v
	}
	if v, ok := item["method"].(string); ok {
		finding.Target = v
	}

	// Extract CVE from msg
	cveRe := regexp.MustCompile(`(?i)CVE-\d{4}-\d{4,}`)
	if m := cveRe.FindString(finding.Title); m != "" {
		finding.CVE = strings.ToUpper(m)
	}

	// Adjust severity based on keywords
	lowerTitle := strings.ToLower(finding.Title)
	if strings.Contains(lowerTitle, "sql injection") ||
		strings.Contains(lowerTitle, "xss") ||
		strings.Contains(lowerTitle, "remote shell") ||
		strings.Contains(lowerTitle, "code execution") {
		finding.Severity = "high"
	}
	if strings.Contains(lowerTitle, "server headers") ||
		strings.Contains(lowerTitle, "cookie") ||
		strings.Contains(lowerTitle, "banner") {
		finding.Severity = "info"
	}

	return finding
}

func parseSslscanOutput(raw string) []vulnScanFinding {
	var findings []vulnScanFinding

	type sslscanTest struct {
		ID         string `xml:"id,attr"`
		Severity   string `xml:"severity,attr"`
		Title      string `xml:"title,attr"`
		CVE        string `xml:"CVE"`
		URL        string `xml:"url"`
		Evidence   string `xml:",innerxml"`
	}

	type sslscanResult struct {
		XMLName struct{}      `xml:"sslscanResults"`
		Tests   []sslscanTest `xml:"test"`
	}

	var result sslscanResult
	if err := xml.Unmarshal([]byte(raw), &result); err != nil {
		return nil
	}

	for _, t := range result.Tests {
		finding := vulnScanFinding{
			Severity:   normalizeSeverity(t.Severity),
			Title:      t.Title,
			CVE:        t.CVE,
			URL:        t.URL,
			Confidence: "likely",
			Evidence:   truncateString(t.Evidence, maxFindingEvidenceSize),
		}
		if finding.Title == "" {
			finding.Title = t.ID
		}
		if finding.Severity == "" {
			finding.Severity = "info"
		}
		findings = append(findings, finding)
	}

	return findings
}

// ---------- Helpers ----------

func normalizeSeverity(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical", "crit":
		return "critical"
	case "high":
		return "high"
	case "medium", "moderate", "warning":
		// "warning" comes from sslscan (Heartbleed, weak ciphers, cert issues) —
		// these are real findings, not informational, so map to medium.
		return "medium"
	case "low":
		return "low"
	case "info", "informational":
		return "info"
	default:
		return "info"
	}
}

var severityOrder = map[string]int{
	"critical": 5,
	"high":     4,
	"medium":   3,
	"low":      2,
	"info":     1,
}

func applySeverityFilter(findings []vulnScanFinding, minSeverity string) []vulnScanFinding {
	if minSeverity == "" {
		return findings
	}
	minVal, ok := severityOrder[strings.ToLower(minSeverity)]
	if !ok {
		return findings
	}
	var filtered []vulnScanFinding
	for _, f := range findings {
		if v, ok := severityOrder[strings.ToLower(f.Severity)]; ok && v >= minVal {
			filtered = append(filtered, f)
		}
	}
	return filtered
}

func capResults(findings []vulnScanFinding, max int) []vulnScanFinding {
	if max <= 0 || len(findings) <= max {
		return findings
	}
	// Sort by severity (highest first) then keep top N
	sort.SliceStable(findings, func(i, j int) bool {
		ci := severityOrder[strings.ToLower(findings[i].Severity)]
		cj := severityOrder[strings.ToLower(findings[j].Severity)]
		return ci > cj
	})
	return findings[:max]
}

func formatVulnScanResults(action VulnScanAction, findings []vulnScanFinding, cmd string) string {
	var b strings.Builder

	// Summary header
	fmt.Fprintf(&b, "## Vulnerability Scan Report\n\n")
	fmt.Fprintf(&b, "**Scanner:** %s\n", action.Scanner)
	fmt.Fprintf(&b, "**Target:** %s\n", action.Target)
	if action.Severity != "" {
		fmt.Fprintf(&b, "**Severity filter:** %s+\n", action.Severity)
	}
	fmt.Fprintf(&b, "**Findings:** %d\n\n", len(findings))

	if len(findings) == 0 {
		b.WriteString("No findings matching the criteria were detected.\n")
		return truncateString(b.String(), maxVulnScanResultSize)
	}

	// Findings summary table
	b.WriteString("## Findings Summary\n\n")
	b.WriteString("| # | Severity | Title | CVE | Target/URL | Confidence |\n")
	b.WriteString("|---|----------|-------|-----|------------|------------|\n")
	for i, f := range findings {
		cve := f.CVE
		if cve == "" {
			cve = "-"
		}
		target := f.URL
		if target == "" {
			target = f.Target
		}
		if target == "" {
			target = action.Target
		}
		fmt.Fprintf(&b, "| %d | %s | %s | %s | %s | %s |\n",
			i+1, f.Severity, truncateString(f.Title, 60), cve,
			truncateString(target, 80), f.Confidence)
	}

	// Findings detail
	b.WriteString("\n## Findings Detail\n\n")
	for i, f := range findings {
		fmt.Fprintf(&b, "### [%s] %s\n", strings.ToUpper(f.Severity), f.Title)
		if f.CVE != "" {
			fmt.Fprintf(&b, "- **CVE:** %s\n", f.CVE)
		}
		if f.CVSS > 0 {
			fmt.Fprintf(&b, "- **CVSS:** %.1f\n", f.CVSS)
		}
		if f.CWE != "" {
			fmt.Fprintf(&b, "- **CWE:** %s\n", f.CWE)
		}
		if f.URL != "" {
			fmt.Fprintf(&b, "- **URL:** %s\n", f.URL)
		}
		if f.Template != "" {
			fmt.Fprintf(&b, "- **Template:** %s\n", f.Template)
		}
		fmt.Fprintf(&b, "- **Confidence:** %s\n", f.Confidence)
		if f.Evidence != "" {
			fmt.Fprintf(&b, "- **Evidence:**\n```\n%s\n```\n", f.Evidence)
		}
		if len(f.References) > 0 {
			b.WriteString("- **References:**\n")
			for _, r := range f.References {
				fmt.Fprintf(&b, "  - %s\n", r)
			}
		}
		b.WriteString("- **Status:** DETECTED ONLY, NOT EXPLOITED\n")
		if i < len(findings)-1 {
			b.WriteString("\n")
		}
	}

	b.WriteString("\n## Coverage Gaps\n")
	b.WriteString("- Scan performed with non-destructive detection only; no exploitation attempted.\n")

	return truncateString(b.String(), maxVulnScanResultSize)
}
