package client

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestScanFindings_SendsRequestAndParsesResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("expected POST, got %s", r.Method)
		}
		if r.URL.Path != "/api/v1/findings/scan" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}

		var req map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decode request body: %v", err)
		}
		if req["table"] != "aws_s3_buckets" {
			t.Fatalf("expected table aws_s3_buckets, got %#v", req["table"])
		}
		if req["limit"] != float64(25) {
			t.Fatalf("expected limit 25, got %#v", req["limit"])
		}

		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"scanned":    2,
			"violations": 1,
			"duration":   "5ms",
			"findings": []map[string]interface{}{
				{"policy_id": "p1", "severity": "HIGH"},
			},
		})
	}))
	defer server.Close()

	c, err := New(Config{
		BaseURL: server.URL,
		APIKey:  "test-key",
	})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}

	resp, err := c.ScanFindings(context.Background(), "aws_s3_buckets", 25)
	if err != nil {
		t.Fatalf("scan findings: %v", err)
	}
	if resp.Scanned != 2 {
		t.Fatalf("expected scanned=2, got %d", resp.Scanned)
	}
	if resp.Violations != 1 {
		t.Fatalf("expected violations=1, got %d", resp.Violations)
	}
	if len(resp.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(resp.Findings))
	}
}
