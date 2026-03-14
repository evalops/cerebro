package api

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/evalops/cerebro/internal/graph"
)

func TestComplianceReportDerivesFromGraphWithoutFindings(t *testing.T) {
	s := newTestServer(t)
	now := time.Date(2026, 3, 13, 18, 0, 0, 0, time.UTC)
	s.app.SecurityGraph.AddNode(&graph.Node{
		ID:        "arn:aws:s3:::graph-audit-bucket",
		Kind:      graph.NodeKindBucket,
		Name:      "graph-audit-bucket",
		Provider:  "aws",
		Account:   "123456789012",
		CreatedAt: now,
		Properties: map[string]any{
			"encrypted":           false,
			"public":              true,
			"block_public_acls":   false,
			"block_public_policy": false,
			"logging_enabled":     false,
			"observed_at":         now,
			"valid_from":          now,
			"recorded_at":         now,
			"transaction_from":    now,
		},
	})

	report := do(t, s, http.MethodGet, "/api/v1/compliance/frameworks/cis-aws-1.5/report", nil)
	if report.Code != http.StatusOK {
		t.Fatalf("report expected 200, got %d: %s", report.Code, report.Body.String())
	}
	body := decodeJSON(t, report)
	if got, ok := body["total_findings"].(float64); !ok || got == 0 {
		t.Fatalf("expected non-zero graph-derived failing asset count, got %v", body["total_findings"])
	}
	reportPayload, ok := body["report"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected report payload, got %#v", body)
	}
	controls, ok := reportPayload["controls"].([]interface{})
	if !ok || len(controls) == 0 {
		t.Fatalf("expected controls payload, got %#v", reportPayload)
	}
	foundGraphControl := false
	for _, item := range controls {
		control, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		if control["control_id"] != "2.1.1" {
			continue
		}
		foundGraphControl = true
		if control["status"] != "failing" {
			t.Fatalf("expected encryption control to fail, got %#v", control)
		}
		if control["evaluation_source"] != "graph" {
			t.Fatalf("expected graph evaluation source, got %#v", control)
		}
	}
	if !foundGraphControl {
		t.Fatalf("expected graph-backed control 2.1.1 in report payload: %#v", controls)
	}
	evidencePayload, ok := body["evidence"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected evidence payload, got %#v", body)
	}
	controlEvidence, ok := evidencePayload["2.1.1"].([]interface{})
	if !ok || len(controlEvidence) == 0 {
		t.Fatalf("expected control evidence for 2.1.1, got %#v", evidencePayload)
	}
	firstEvidence, ok := controlEvidence[0].(map[string]interface{})
	if !ok {
		t.Fatalf("expected evidence object, got %#v", controlEvidence[0])
	}
	for _, field := range []string{"entity_id", "entity_name", "entity_kind", "facet_id"} {
		if _, exists := firstEvidence[field]; exists {
			t.Fatalf("expected redacted evidence to omit %s, got %#v", field, firstEvidence)
		}
	}

	export := do(t, s, http.MethodGet, "/api/v1/compliance/frameworks/cis-aws-1.5/export", nil)
	if export.Code != http.StatusOK {
		t.Fatalf("export expected 200, got %d: %s", export.Code, export.Body.String())
	}
	bodyBytes := export.Body.Bytes()
	zr, err := zip.NewReader(bytes.NewReader(bodyBytes), int64(len(bodyBytes)))
	if err != nil {
		t.Fatalf("invalid zip payload: %v", err)
	}

	var controlsFile *zip.File
	for _, file := range zr.File {
		if file.Name == "controls.json" {
			controlsFile = file
			break
		}
	}
	if controlsFile == nil {
		t.Fatal("missing controls.json in audit export")
	}
	rc, err := controlsFile.Open()
	if err != nil {
		t.Fatalf("open controls entry: %v", err)
	}
	defer func() { _ = rc.Close() }()

	var controlsPayload []map[string]any
	if err := json.NewDecoder(rc).Decode(&controlsPayload); err != nil {
		t.Fatalf("decode controls export: %v", err)
	}
	foundEvidence := false
	for _, item := range controlsPayload {
		if item["control_id"] != "2.1.1" {
			continue
		}
		foundEvidence = true
		if item["evaluation_source"] != "graph" {
			t.Fatalf("expected graph evaluation source in export, got %#v", item)
		}
		evidence, ok := item["evidence"].([]any)
		if !ok || len(evidence) == 0 {
			t.Fatalf("expected graph evidence in export, got %#v", item)
		}
		redacted, ok := evidence[0].(map[string]any)
		if !ok {
			t.Fatalf("expected evidence entry object, got %#v", evidence[0])
		}
		for _, field := range []string{"entity_id", "entity_name", "entity_kind", "facet_id"} {
			if _, exists := redacted[field]; exists {
				t.Fatalf("expected exported evidence to omit %s, got %#v", field, redacted)
			}
		}
	}
	if !foundEvidence {
		t.Fatalf("expected control 2.1.1 in exported controls payload: %#v", controlsPayload)
	}
}
