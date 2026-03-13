package api

import (
	"net/http"
	"testing"
	"time"

	"github.com/evalops/cerebro/internal/graph"
)

func TestGraphAccessReviewEndpointsUseSharedIdentityService(t *testing.T) {
	s := newTestServer(t)
	lastLogin := time.Now().Add(-120 * 24 * time.Hour).UTC().Format(time.RFC3339)
	s.app.SecurityGraph.AddNode(&graph.Node{
		ID:        "user:alice",
		Kind:      graph.NodeKindUser,
		Name:      "alice@example.com",
		Provider:  "aws",
		Account:   "123456789012",
		CreatedAt: time.Now().Add(-400 * 24 * time.Hour).UTC(),
		Properties: map[string]any{
			"email":      "alice@example.com",
			"last_login": lastLogin,
		},
	})
	s.app.SecurityGraph.AddNode(&graph.Node{
		ID:        "person:bob",
		Kind:      graph.NodeKindPerson,
		Name:      "Bob Reviewer",
		Provider:  "internal",
		Account:   "corp",
		CreatedAt: time.Now().Add(-500 * 24 * time.Hour).UTC(),
	})
	s.app.SecurityGraph.AddNode(&graph.Node{
		ID:        "bucket:prod-data",
		Kind:      graph.NodeKindBucket,
		Name:      "prod-data",
		Provider:  "aws",
		Account:   "123456789012",
		Risk:      graph.RiskCritical,
		CreatedAt: time.Now().Add(-500 * 24 * time.Hour).UTC(),
	})
	s.app.SecurityGraph.AddEdge(&graph.Edge{ID: "alice-admin", Source: "user:alice", Target: "bucket:prod-data", Kind: graph.EdgeKindCanAdmin, Effect: graph.EdgeEffectAllow})
	s.app.SecurityGraph.AddEdge(&graph.Edge{ID: "bob-owner", Source: "person:bob", Target: "bucket:prod-data", Kind: graph.EdgeKindOwns, Effect: graph.EdgeEffectAllow})

	create := do(t, s, http.MethodPost, "/api/v1/graph/access-reviews", map[string]any{
		"name":       "Prod graph review",
		"created_by": "secops@example.com",
		"scope": map[string]any{
			"type":       "resource",
			"resources":  []string{"bucket:prod-data"},
			"principals": []string{"user:alice"},
		},
	})
	if create.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d body=%s", create.Code, create.Body.String())
	}
	created := decodeJSON(t, create)
	if created["generation_source"] != "graph" {
		t.Fatalf("expected graph generation source, got %#v", created)
	}
	items, ok := created["items"].([]interface{})
	if !ok || len(items) != 1 {
		t.Fatalf("expected 1 generated review item, got %#v", created["items"])
	}

	list := do(t, s, http.MethodGet, "/api/v1/graph/access-reviews", nil)
	if list.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", list.Code)
	}
	body := decodeJSON(t, list)
	if body["count"].(float64) < 1 {
		t.Fatalf("expected persisted graph access review, got %#v", body)
	}
}
