package tools

import (
	"strings"
	"testing"
)

func TestParseNucleiOutput(t *testing.T) {
	raw := `{"template-id":"CVE-2021-44228","info":{"name":"Log4j Remote Code Execution","severity":"critical","classification":{"cve-id":["CVE-2021-44228"],"cvss-score":10.0,"cwe-id":["CWE-502"]},"reference":["https://nvd.nist.gov/vuln/detail/CVE-2021-44228"]},"matched-at":"http://example.com:8443/login"}
{"template-id":"tech-detect","info":{"name":"WordPress Detection","severity":"info"},"matched-at":"http://example.com"}`

	findings := parseNucleiOutput(raw)

	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(findings))
	}

	// First finding: critical Log4j
	f := findings[0]
	if f.Severity != "critical" {
		t.Errorf("expected severity 'critical', got '%s'", f.Severity)
	}
	if f.Title != "Log4j Remote Code Execution" {
		t.Errorf("expected title 'Log4j Remote Code Execution', got '%s'", f.Title)
	}
	if f.CVE != "CVE-2021-44228" {
		t.Errorf("expected CVE 'CVE-2021-44228', got '%s'", f.CVE)
	}
	if f.CVSS != 10.0 {
		t.Errorf("expected CVSS 10.0, got %f", f.CVSS)
	}
	if f.Confidence != "confirmed" {
		t.Errorf("expected confidence 'confirmed', got '%s'", f.Confidence)
	}
	if f.URL != "http://example.com:8443/login" {
		t.Errorf("expected URL 'http://example.com:8443/login', got '%s'", f.URL)
	}

	// Second finding: info
	f2 := findings[1]
	if f2.Severity != "info" {
		t.Errorf("expected severity 'info', got '%s'", f2.Severity)
	}
}

func TestParseNucleiOutput_EmptyAndInvalid(t *testing.T) {
	findings := parseNucleiOutput("")
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for empty input, got %d", len(findings))
	}

	findings = parseNucleiOutput("not json\nalso not json\n")
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for invalid input, got %d", len(findings))
	}

	// Mixed: one valid, one invalid
	raw := `not json here
{"template-id":"x","info":{"name":"Test","severity":"high"}}`
	findings = parseNucleiOutput(raw)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding from mixed input, got %d", len(findings))
	}
	if findings[0].Severity != "high" {
		t.Errorf("expected severity 'high', got '%s'", findings[0].Severity)
	}
}

func TestParseNiktoOutput(t *testing.T) {
	raw := `{"vulnerabilities":[
		{"id":"001","msg":"Server may leak inodes via ETags header","url":"http://example.com/","method":"GET"},
		{"id":"002","msg":"SQL injection found in parameter id","url":"http://example.com/page?id=1","method":"GET"},
		{"id":"003","msg":"Cookie sent without Secure flag","url":"http://example.com/","method":"GET"}
	]}`

	findings := parseNiktoOutput(raw)

	if len(findings) != 3 {
		t.Fatalf("expected 3 findings, got %d", len(findings))
	}

	// Second finding: SQL injection → high
	if findings[1].Severity != "high" {
		t.Errorf("expected SQL injection severity 'high', got '%s'", findings[1].Severity)
	}
	if findings[1].Title == "" {
		t.Error("expected non-empty title")
	}

	// Third finding: Cookie → info
	if findings[2].Severity != "info" {
		t.Errorf("expected cookie severity 'info', got '%s'", findings[2].Severity)
	}
}

func TestParseNiktoOutput_WithCVE(t *testing.T) {
	raw := `{"vulnerabilities":[
		{"id":"004","msg":"Found CVE-2021-44228 vulnerability in log4j","url":"http://example.com/","method":"GET"}
	]}`

	findings := parseNiktoOutput(raw)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].CVE != "CVE-2021-44228" {
		t.Errorf("expected CVE 'CVE-2021-44228', got '%s'", findings[0].CVE)
	}
}

func TestParseSslscanOutput(t *testing.T) {
	raw := `<?xml version="1.0"?>
<sslscanResults>
  <test id="ssl3" severity="CRITICAL" title="SSL 3.0 Supported">
    <CVE>CVE-2014-3566</CVE>
    Vulnerable to POODLE attack
  </test>
  <test id="heartbleed" severity="WARNING" title="Heartbleed Vulnerable">
    Vulnerable to Heartbleed
  </test>
  <test id="tls12" severity="INFO" title="TLS 1.2 Supported">
    TLS 1.2 is supported
  </test>
</sslscanResults>`

	findings := parseSslscanOutput(raw)

	if len(findings) != 3 {
		t.Fatalf("expected 3 findings, got %d", len(findings))
	}

	if findings[0].Severity != "critical" {
		t.Errorf("expected severity 'critical', got '%s'", findings[0].Severity)
	}
	if findings[0].Title != "SSL 3.0 Supported" {
		t.Errorf("expected title 'SSL 3.0 Supported', got '%s'", findings[0].Title)
	}
	if findings[0].CVE != "CVE-2014-3566" {
		t.Errorf("expected CVE 'CVE-2014-3566', got '%s'", findings[0].CVE)
	}

	// "WARNING" (Heartbleed) normalizes to "medium" per normalizeSeverity's
	// sslscan-aware mapping — these are real findings, not informational.
	if findings[1].Severity != "medium" {
		t.Errorf("expected severity 'medium' for WARNING, got '%s'", findings[1].Severity)
	}
	if findings[1].Title != "Heartbleed Vulnerable" {
		t.Errorf("expected title 'Heartbleed Vulnerable', got '%s'", findings[1].Title)
	}

	if findings[2].Severity != "info" {
		t.Errorf("expected severity 'info' for INFO, got '%s'", findings[2].Severity)
	}
}

func TestNormalizeSeverity(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"critical", "critical"},
		{"CRITICAL", "critical"},
		{"crit", "critical"},
		{"high", "high"},
		{"HIGH", "high"},
		{"medium", "medium"},
		{"moderate", "medium"},
		{"warning", "medium"},
		{"WARNING", "medium"},
		{"low", "low"},
		{"info", "info"},
		{"informational", "info"},
		{"unknown", "info"},
		{"", "info"},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := normalizeSeverity(tt.input)
			if got != tt.want {
				t.Errorf("normalizeSeverity(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestApplySeverityFilter(t *testing.T) {
	findings := []vulnScanFinding{
		{Severity: "critical", Title: "A"},
		{Severity: "high", Title: "B"},
		{Severity: "medium", Title: "C"},
		{Severity: "low", Title: "D"},
		{Severity: "info", Title: "E"},
	}

	// Filter high+ → should keep critical, high
	filtered := applySeverityFilter(findings, "high")
	if len(filtered) != 2 {
		t.Fatalf("expected 2 findings for 'high' filter, got %d", len(filtered))
	}

	// No filter → all
	filtered = applySeverityFilter(findings, "")
	if len(filtered) != 5 {
		t.Fatalf("expected 5 findings for empty filter, got %d", len(filtered))
	}

	// Info filter → all
	filtered = applySeverityFilter(findings, "info")
	if len(filtered) != 5 {
		t.Fatalf("expected 5 findings for 'info' filter, got %d", len(filtered))
	}
}

func TestCapResults(t *testing.T) {
	findings := []vulnScanFinding{
		{Severity: "low", Title: "D"},
		{Severity: "critical", Title: "A"},
		{Severity: "medium", Title: "C"},
		{Severity: "high", Title: "B"},
		{Severity: "info", Title: "E"},
	}

	// Cap to 3 → should keep top 3 by severity (critical, high, medium)
	capped := capResults(findings, 3)
	if len(capped) != 3 {
		t.Fatalf("expected 3 findings after cap, got %d", len(capped))
	}
	if capped[0].Severity != "critical" {
		t.Errorf("expected first to be 'critical', got '%s'", capped[0].Severity)
	}
	if capped[1].Severity != "high" {
		t.Errorf("expected second to be 'high', got '%s'", capped[1].Severity)
	}
	if capped[2].Severity != "medium" {
		t.Errorf("expected third to be 'medium', got '%s'", capped[2].Severity)
	}

	// Cap to 0 → no cap
	capped = capResults(findings, 0)
	if len(capped) != 5 {
		t.Fatalf("expected 5 findings with cap=0, got %d", len(capped))
	}
}

func TestBuildNucleiCommand(t *testing.T) {
	v := &vulnscan{rateLimit: 50}

	action := VulnScanAction{
		Target:    "https://example.com:8443",
		Scanner:   "nuclei",
		RateLimit: 30,
	}

	cmd := v.buildNucleiCommand(action, "/tmp/out.jsonl", 1790)

	// Check essential flags
	if !strings.Contains(cmd, "nuclei") {
		t.Error("command should contain 'nuclei'")
	}
	if !strings.Contains(cmd, "-u https://example.com:8443") {
		t.Error("command should contain target with -u flag")
	}
	if !strings.Contains(cmd, "-rl 30") {
		t.Error("command should contain -rl 30 for rate limit")
	}
	if !strings.Contains(cmd, "-c 15") {
		t.Error("command should contain -c 15 for concurrency")
	}
	if !strings.Contains(cmd, "-jsonl") {
		t.Error("command should contain -jsonl for output format")
	}
	if !strings.Contains(cmd, "-o /tmp/out.jsonl") {
		t.Error("command should contain -o /tmp/out.jsonl for output file")
	}
	if !strings.Contains(cmd, "-nc") {
		t.Error("command should contain -nc for no color")
	}
	if !strings.Contains(cmd, "-silent") {
		t.Error("command should contain -silent")
	}
	if !strings.Contains(cmd, "timeout 1790") {
		t.Error("command should contain 'timeout 1790' wrapper")
	}
}

func TestBuildNiktoCommand(t *testing.T) {
	v := &vulnscan{}

	action := VulnScanAction{
		Target:  "https://example.com",
		Scanner: "nikto",
		Ports:   "80,443",
	}

	cmd := v.buildNiktoCommand(action, "/tmp/out.json", 600)

	if !strings.Contains(cmd, "nikto") {
		t.Error("command should contain 'nikto'")
	}
	if !strings.Contains(cmd, "-h https://example.com") {
		t.Error("command should contain -h target")
	}
	if !strings.Contains(cmd, "-p 80,443") {
		t.Error("command should contain -p 80,443 for ports")
	}
	if !strings.Contains(cmd, "-Format json") {
		t.Error("command should contain -Format json")
	}
	if !strings.Contains(cmd, "-o /tmp/out.json") {
		t.Error("command should contain -o /tmp/out.json")
	}
	if !strings.Contains(cmd, "-Tuning 123b") {
		t.Error("command should contain -Tuning 123b")
	}
	if !strings.Contains(cmd, "timeout 600") {
		t.Error("command should contain 'timeout 600' wrapper")
	}
}

func TestBuildSslscanCommand(t *testing.T) {
	v := &vulnscan{}

	action := VulnScanAction{
		Target:  "example.com",
		Scanner: "sslscan",
	}

	cmd := v.buildSslscanCommand(action, "/tmp/out.xml", 300)

	if !strings.Contains(cmd, "sslscan") {
		t.Error("command should contain 'sslscan'")
	}
	if !strings.Contains(cmd, "--xml=/tmp/out.xml") {
		t.Error("command should contain --xml=/tmp/out.xml")
	}
	if !strings.Contains(cmd, "example.com") {
		t.Error("command should contain target")
	}
	if !strings.Contains(cmd, "timeout 300") {
		t.Error("command should contain 'timeout 300' wrapper")
	}
}

func TestValidateTarget(t *testing.T) {
	v := &vulnscan{allowLocal: false}

	// Empty target
	if err := v.validateTarget(""); err == nil {
		t.Error("expected error for empty target")
	}

	// Loopback IP (should be rejected)
	if err := v.validateTarget("127.0.0.1"); err == nil {
		t.Error("expected error for loopback IP")
	}

	// Private IP (should be rejected)
	if err := v.validateTarget("192.168.1.1"); err == nil {
		t.Error("expected error for private IP")
	}

	// Public IP (should be accepted)
	if err := v.validateTarget("8.8.8.8"); err != nil {
		t.Errorf("expected no error for public IP, got %v", err)
	}

	// Public hostname (should be accepted)
	if err := v.validateTarget("example.com"); err != nil {
		t.Errorf("expected no error for hostname, got %v", err)
	}

	// URL with public hostname (should be accepted)
	if err := v.validateTarget("https://example.com:8443"); err != nil {
		t.Errorf("expected no error for URL, got %v", err)
	}

	// With allowLocal=true, loopback should be accepted
	v.allowLocal = true
	if err := v.validateTarget("127.0.0.1"); err != nil {
		t.Errorf("expected no error for loopback with allowLocal, got %v", err)
	}
}

func TestResolveRateLimit(t *testing.T) {
	v := &vulnscan{rateLimit: 50}

	// Default rate limit
	if rl := v.resolveRateLimit(0); rl != 50 {
		t.Errorf("expected 50, got %d", rl)
	}

	// Custom rate limit within cap
	if rl := v.resolveRateLimit(30); rl != 30 {
		t.Errorf("expected 30, got %d", rl)
	}

	// Over hard cap → should be capped to 100
	if rl := v.resolveRateLimit(200); rl != vulnScanHardRateLimit {
		t.Errorf("expected %d, got %d", vulnScanHardRateLimit, rl)
	}

	// Zero default with zero action → fallback to 50
	v.rateLimit = 0
	if rl := v.resolveRateLimit(0); rl != 50 {
		t.Errorf("expected 50, got %d", rl)
	}
}

func TestFormatVulnScanResults(t *testing.T) {
	findings := []vulnScanFinding{
		{
			Severity:   "critical",
			Title:      "Log4j RCE",
			CVE:        "CVE-2021-44228",
			CVSS:       10.0,
			URL:        "http://example.com/login",
			Confidence: "confirmed",
			Evidence:   "proof of concept here",
		},
		{
			Severity:   "medium",
			Title:      "Missing Security Header",
			Confidence: "likely",
			Evidence:   "no X-Frame-Options",
		},
	}

	action := VulnScanAction{
		Target:  "https://example.com",
		Scanner: "nuclei",
	}

	result := formatVulnScanResults(action, findings, "nuclei -u https://example.com")

	if result == "" {
		t.Fatal("expected non-empty result")
	}
	if !strings.Contains(result, "Vulnerability Scan Report") {
		t.Error("result should contain report header")
	}
	if !strings.Contains(result, "Log4j RCE") {
		t.Error("result should contain finding title")
	}
	if !strings.Contains(result, "CVE-2021-44228") {
		t.Error("result should contain CVE")
	}
	if !strings.Contains(result, "Findings Summary") {
		t.Error("result should contain findings summary section")
	}
	if !strings.Contains(result, "Findings Detail") {
		t.Error("result should contain findings detail section")
	}
	if !strings.Contains(result, "Coverage Gaps") {
		t.Error("result should contain coverage gaps section")
	}
	if !strings.Contains(result, "DETECTED ONLY, NOT EXPLOITED") {
		t.Error("result should contain non-exploitation status")
	}
}

func TestFormatVulnScanResults_NoFindings(t *testing.T) {
	action := VulnScanAction{
		Target:  "https://example.com",
		Scanner: "nuclei",
	}

	result := formatVulnScanResults(action, nil, "nuclei -u https://example.com")

	if !strings.Contains(result, "No findings") {
		t.Error("result should mention no findings")
	}
}
