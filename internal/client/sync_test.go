package client

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestBackfillRelationshipIDs_SendsBatchSizeAndParsesResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("expected POST, got %s", r.Method)
		}
		if r.URL.Path != "/api/v1/sync/backfill-relationships" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}

		var req map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decode request body: %v", err)
		}
		if req["batch_size"] != float64(250) {
			t.Fatalf("expected batch_size=250, got %#v", req["batch_size"])
		}

		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"scanned": 10,
			"updated": 4,
			"deleted": 3,
			"skipped": 3,
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

	stats, err := c.BackfillRelationshipIDs(context.Background(), 250)
	if err != nil {
		t.Fatalf("BackfillRelationshipIDs returned error: %v", err)
	}
	if stats.Scanned != 10 || stats.Updated != 4 || stats.Deleted != 3 || stats.Skipped != 3 {
		t.Fatalf("unexpected stats: %+v", stats)
	}
}

func TestBackfillRelationshipIDs_ZeroBatchUsesDefaultServerBehavior(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/sync/backfill-relationships" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}

		var req map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil && !errors.Is(err, io.EOF) {
			t.Fatalf("decode request body: %v", err)
		}
		if len(req) != 0 {
			t.Fatalf("expected empty request body for default batch size, got %#v", req)
		}

		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"scanned": 1,
			"updated": 1,
			"deleted": 0,
			"skipped": 0,
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

	stats, err := c.BackfillRelationshipIDs(context.Background(), 0)
	if err != nil {
		t.Fatalf("BackfillRelationshipIDs returned error: %v", err)
	}
	if stats.Scanned != 1 || stats.Updated != 1 {
		t.Fatalf("unexpected stats: %+v", stats)
	}
}
