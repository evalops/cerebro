package filesystemanalyzer

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
)

// GitleaksScanner wraps `gitleaks dir` for filesystem-root secret scanning.
type GitleaksScanner struct {
	binaryPath string
}

func NewGitleaksScanner(binaryPath string) *GitleaksScanner {
	if strings.TrimSpace(binaryPath) == "" {
		binaryPath = "gitleaks"
	}
	return &GitleaksScanner{binaryPath: binaryPath}
}

func (s *GitleaksScanner) ScanFilesystem(ctx context.Context, rootfsPath string) (*SecretScanResult, error) {
	if strings.TrimSpace(s.binaryPath) == "" {
		return nil, fmt.Errorf("gitleaks binary path is required")
	}
	rootfsPath = strings.TrimSpace(rootfsPath)
	if rootfsPath == "" {
		return nil, fmt.Errorf("filesystem path is required")
	}
	if strings.ContainsAny(rootfsPath, "\r\n") {
		return nil, fmt.Errorf("filesystem path must not contain newlines")
	}
	absPath, err := filepath.Abs(rootfsPath)
	if err != nil {
		return nil, fmt.Errorf("resolve filesystem path %s: %w", rootfsPath, err)
	}

	cmd := exec.CommandContext(
		ctx,
		s.binaryPath,
		"dir",
		"--no-banner",
		"--log-level", "error",
		"--exit-code", "0",
		"--report-format", "json",
		"--report-path", "-",
		absPath,
	) // #nosec G204 -- fixed binary/arguments, no shell interpolation
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	output, err := cmd.Output()
	if err != nil {
		stderrText := strings.TrimSpace(stderr.String())
		if stderrText != "" {
			return nil, fmt.Errorf("gitleaks dir scan failed: %s", stderrText)
		}
		return nil, fmt.Errorf("gitleaks dir scan failed: %w", err)
	}
	findings, err := parseGitleaksOutput(output)
	if err != nil {
		return nil, err
	}
	return &SecretScanResult{
		Engine:   "gitleaks",
		Findings: findings,
	}, nil
}

type gitleaksFinding struct {
	RuleID      string
	Description string
	StartLine   int
	Match       string
	Secret      string
	File        string
	Fingerprint string
}

func parseGitleaksOutput(data []byte) ([]SecretFinding, error) {
	data = bytes.TrimSpace(data)
	if len(data) == 0 || bytes.Equal(data, []byte("null")) {
		return nil, nil
	}
	var raw []gitleaksFinding
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parse gitleaks report: %w", err)
	}
	findings := make([]SecretFinding, 0, len(raw))
	for _, finding := range raw {
		findings = append(findings, normalizeSecretFinding(convertGitleaksFinding(finding)))
	}
	return findings, nil
}

func convertGitleaksFinding(f gitleaksFinding) SecretFinding {
	ruleType := normalizeGitleaksRuleID(f.RuleID)
	lineNo := f.StartLine
	if lineNo <= 0 {
		lineNo = 1
	}
	filePath := strings.TrimPrefix(strings.TrimSpace(f.File), "./")
	matchSource := firstNonEmpty(strings.TrimSpace(f.Secret), strings.TrimSpace(f.Match), strings.TrimSpace(f.Fingerprint), strings.TrimSpace(f.RuleID))
	description := strings.TrimSpace(f.Description)
	if description == "" {
		description = fmt.Sprintf("Potential secret detected by Gitleaks rule %s.", firstNonEmpty(strings.TrimSpace(f.RuleID), "unknown"))
	}
	converted := SecretFinding{
		Type:        ruleType,
		Severity:    gitleaksSeverity(ruleType),
		Path:        filePath,
		Line:        lineNo,
		Match:       fingerprintSecretMatch(matchSource),
		Description: description,
	}
	if ref, ok := secretReferenceFromExternalMatch(ruleType, firstNonEmpty(f.Secret, f.Match)); ok {
		converted.References = append(converted.References, ref)
	}
	return converted
}

func normalizeGitleaksRuleID(ruleID string) string {
	candidate := sanitizeSecretType(ruleID)
	switch {
	case strings.Contains(candidate, "aws") && strings.Contains(candidate, "access"):
		return "aws_access_key"
	case strings.Contains(candidate, "github"):
		return "github_token"
	case strings.Contains(candidate, "gitlab"):
		return "gitlab_token"
	case strings.Contains(candidate, "slack"):
		return "slack_token"
	case strings.Contains(candidate, "stripe"):
		return "stripe_api_key"
	case strings.Contains(candidate, "twilio"):
		return "twilio_api_key"
	case strings.Contains(candidate, "sendgrid"):
		return "sendgrid_api_key"
	case strings.Contains(candidate, "mailgun"):
		return "mailgun_api_key"
	case strings.Contains(candidate, "jwt"):
		return "jwt_token"
	case strings.Contains(candidate, "docker"):
		return "docker_registry_credentials"
	case strings.Contains(candidate, "private_key"), strings.Contains(candidate, "private") && strings.Contains(candidate, "key"):
		return "private_key"
	case strings.Contains(candidate, "database"), strings.Contains(candidate, "connection"), strings.Contains(candidate, "jdbc"), strings.Contains(candidate, "mongodb"), strings.Contains(candidate, "postgres"), strings.Contains(candidate, "mysql"), strings.Contains(candidate, "redis"):
		return "database_connection_string"
	case candidate != "":
		return candidate
	default:
		return "external_secret"
	}
}

func gitleaksSeverity(secretType string) string {
	switch secretType {
	case "aws_access_key", "database_connection_string", "private_key", "gcp_service_account_key":
		return "critical"
	case "external_secret", "generic_api_key", "generic_credential", "high_entropy_string":
		return "medium"
	default:
		return "high"
	}
}

func secretReferenceFromExternalMatch(secretType, match string) (SecretReference, bool) {
	match = strings.TrimSpace(match)
	switch secretType {
	case "aws_access_key":
		if key := awsAccessKeyPattern.FindString(match); key != "" {
			return SecretReference{Kind: "cloud_identity", Provider: "aws", Identifier: strings.TrimSpace(key)}, true
		}
	case "database_connection_string":
		if ref, ok := parseDatabaseConnectionReference(match); ok {
			return ref, true
		}
	}
	return SecretReference{}, false
}
