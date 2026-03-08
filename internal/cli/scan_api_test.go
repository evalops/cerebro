package cli

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type scanCLIState struct {
	tables               []string
	limit                int
	dryRun               bool
	output               string
	full                 bool
	toxicCombos          bool
	useGraph             bool
	extractRelationships bool
	preflight            bool
	localFixture         string
	snapshotDir          string
}

func snapshotScanCLIState() scanCLIState {
	return scanCLIState{
		tables:               append([]string(nil), scanTables...),
		limit:                scanLimit,
		dryRun:               scanDryRun,
		output:               scanOutput,
		full:                 scanFull,
		toxicCombos:          scanToxicCombos,
		useGraph:             scanUseGraph,
		extractRelationships: scanExtractRelationships,
		preflight:            scanPreflight,
		localFixture:         scanLocalFixture,
		snapshotDir:          scanSnapshotDir,
	}
}

func restoreScanCLIState(state scanCLIState) {
	scanTables = append([]string(nil), state.tables...)
	scanLimit = state.limit
	scanDryRun = state.dryRun
	scanOutput = state.output
	scanFull = state.full
	scanToxicCombos = state.toxicCombos
	scanUseGraph = state.useGraph
	scanExtractRelationships = state.extractRelationships
	scanPreflight = state.preflight
	scanLocalFixture = state.localFixture
	scanSnapshotDir = state.snapshotDir
}

func TestRunScanViaAPI_AggregatesJSONOutput(t *testing.T) {
	state := snapshotScanCLIState()
	t.Cleanup(func() { restoreScanCLIState(state) })

	expectedTables := []string{"aws_s3_buckets", "aws_iam_roles"}
	requestIndex := 0

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("expected POST, got %s", r.Method)
		}
		if r.URL.Path != "/api/v1/findings/scan" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}

		var req map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		if req["table"] != expectedTables[requestIndex] {
			t.Fatalf("expected table %q, got %#v", expectedTables[requestIndex], req["table"])
		}
		if req["limit"] != float64(25) {
			t.Fatalf("expected limit=25, got %#v", req["limit"])
		}

		response := map[string]interface{}{
			"scanned":    requestIndex + 1,
			"violations": 1,
			"duration":   "5ms",
			"findings": []map[string]interface{}{
				{"severity": "HIGH", "policy_id": "policy-1", "resource_id": expectedTables[requestIndex]},
			},
		}
		requestIndex++
		_ = json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	t.Setenv(envCLIAPIURL, server.URL)
	scanLimit = 25
	scanOutput = FormatJSON

	output := captureStdout(t, func() {
		if err := runScanViaAPI(context.Background(), expectedTables); err != nil {
			t.Fatalf("runScanViaAPI failed: %v", err)
		}
	})

	var payload map[string]interface{}
	if err := json.Unmarshal([]byte(output), &payload); err != nil {
		t.Fatalf("decode output json: %v (output=%s)", err, output)
	}
	if payload["mode"] != "api" {
		t.Fatalf("expected mode=api, got %#v", payload["mode"])
	}
	if payload["scanned"] != float64(3) {
		t.Fatalf("expected scanned=3, got %#v", payload["scanned"])
	}
	if payload["violations"] != float64(2) {
		t.Fatalf("expected violations=2, got %#v", payload["violations"])
	}
	findings, ok := payload["findings"].([]interface{})
	if !ok || len(findings) != 2 {
		t.Fatalf("expected two findings, got %#v", payload["findings"])
	}
}

func TestRunScanViaAPI_ReturnsTransportError(t *testing.T) {
	state := snapshotScanCLIState()
	t.Cleanup(func() { restoreScanCLIState(state) })

	t.Setenv(envCLIAPIURL, "http://127.0.0.1:1")
	scanOutput = FormatJSON

	err := runScanViaAPI(context.Background(), []string{"aws_s3_buckets"})
	if err == nil {
		t.Fatal("expected api transport error")
	}
}

func TestScanSupportsAPIMode(t *testing.T) {
	state := snapshotScanCLIState()
	t.Cleanup(func() { restoreScanCLIState(state) })

	scanDryRun = false
	scanExtractRelationships = false
	scanFull = false
	scanToxicCombos = false
	scanUseGraph = false

	ok, reason := scanSupportsAPIMode(false)
	if !ok {
		t.Fatalf("expected api compatibility, got false: %s", reason)
	}

	scanToxicCombos = true
	ok, reason = scanSupportsAPIMode(false)
	if ok || !strings.Contains(reason, "--toxic-combos") {
		t.Fatalf("expected toxic-combo incompatibility, got ok=%v reason=%q", ok, reason)
	}

	scanToxicCombos = false
	scanUseGraph = true
	ok, reason = scanSupportsAPIMode(false)
	if ok || !strings.Contains(reason, "--graph") {
		t.Fatalf("expected graph incompatibility, got ok=%v reason=%q", ok, reason)
	}

	scanUseGraph = false
	ok, reason = scanSupportsAPIMode(true)
	if ok || !strings.Contains(reason, "local dataset mode") {
		t.Fatalf("expected local-mode incompatibility, got ok=%v reason=%q", ok, reason)
	}
}
