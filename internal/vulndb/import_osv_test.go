package vulndb

import (
	"context"
	"strings"
	"testing"
)

func TestImportEPSSCSVRejectsOversizedInputs(t *testing.T) {
	store, err := NewSQLiteStore(t.TempDir() + "/vulndb.db")
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	defer func() { _ = store.Close() }()
	service := NewService(store)

	previousBytes := maxEPSSImportBytes
	previousRows := maxEPSSImportRows
	maxEPSSImportBytes = 32
	maxEPSSImportRows = 2
	t.Cleanup(func() {
		maxEPSSImportBytes = previousBytes
		maxEPSSImportRows = previousRows
	})

	_, err = service.ImportEPSSCSV(context.Background(), "epss-test", strings.NewReader("cve,epss,percentile\nCVE-2026-0001,0.1,0.2\nCVE-2026-0002,0.2,0.3\n"))
	if err == nil {
		t.Fatal("expected oversized EPSS input to fail")
	}
	if !strings.Contains(err.Error(), "exceeded maximum") {
		t.Fatalf("expected maximum-bound error, got %v", err)
	}
}

func TestImportEPSSCSVSkipsCommentLines(t *testing.T) {
	store, err := NewSQLiteStore(t.TempDir() + "/vulndb.db")
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	defer func() { _ = store.Close() }()
	service := NewService(store)

	if err := store.UpsertAdvisory(context.Background(), Vulnerability{
		ID:      "GHSA-test-0001",
		Aliases: []string{"CVE-2026-0001"},
		Source:  "osv",
	}, nil); err != nil {
		t.Fatalf("UpsertAdvisory: %v", err)
	}

	report, err := service.ImportEPSSCSV(context.Background(), "epss-test", strings.NewReader("# EPSS v4\ncve,epss,percentile\nCVE-2026-0001,0.91,0.99\n"))
	if err != nil {
		t.Fatalf("ImportEPSSCSV: %v", err)
	}
	if report.Imported != 1 || report.MatchedEPSS != 1 {
		t.Fatalf("expected comment-prefixed EPSS import to match one record, got %#v", report)
	}
}

func TestExtractOSVSeverityParsesCVSSVectors(t *testing.T) {
	severity, score := extractOSVSeverity(osvAdvisory{
		Severity: []osvSeverity{{
			Type:  "CVSS_V3",
			Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
		}},
	})
	if severity != "critical" {
		t.Fatalf("expected critical severity from CVSS vector, got %q", severity)
	}
	if score < 9.8 {
		t.Fatalf("expected CVSS score near 9.8, got %f", score)
	}
}
