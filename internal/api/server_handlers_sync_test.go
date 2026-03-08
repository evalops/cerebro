package api

import (
	"net/http"
	"testing"
)

func TestBackfillRelationshipIDs_RequiresSnowflake(t *testing.T) {
	s := newTestServer(t)

	w := do(t, s, http.MethodPost, "/api/v1/sync/backfill-relationships", map[string]interface{}{
		"batch_size": 100,
	})
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d: %s", w.Code, w.Body.String())
	}
}

func TestBackfillRelationshipIDs_InvalidRequest(t *testing.T) {
	s := newTestServer(t)

	w := do(t, s, http.MethodPost, "/api/v1/sync/backfill-relationships", "not-json")
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid request, got %d: %s", w.Code, w.Body.String())
	}
}
