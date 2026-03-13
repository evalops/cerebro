package api

import (
	"context"
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

func TestGraphAccessReviewDecisionRejectsItemFromAnotherReview(t *testing.T) {
	s := newTestServer(t)
	now := time.Now().UTC()
	s.app.SecurityGraph.AddNode(&graph.Node{
		ID:        "user:alice",
		Kind:      graph.NodeKindUser,
		Name:      "alice@example.com",
		Provider:  "aws",
		Account:   "123456789012",
		CreatedAt: now.Add(-400 * 24 * time.Hour),
	})
	s.app.SecurityGraph.AddNode(&graph.Node{
		ID:        "bucket:prod-a",
		Kind:      graph.NodeKindBucket,
		Name:      "prod-a",
		Provider:  "aws",
		Account:   "123456789012",
		Risk:      graph.RiskCritical,
		CreatedAt: now.Add(-500 * 24 * time.Hour),
	})
	s.app.SecurityGraph.AddNode(&graph.Node{
		ID:        "bucket:prod-b",
		Kind:      graph.NodeKindBucket,
		Name:      "prod-b",
		Provider:  "aws",
		Account:   "123456789012",
		Risk:      graph.RiskCritical,
		CreatedAt: now.Add(-500 * 24 * time.Hour),
	})
	s.app.SecurityGraph.AddEdge(&graph.Edge{ID: "alice-admin-a", Source: "user:alice", Target: "bucket:prod-a", Kind: graph.EdgeKindCanAdmin, Effect: graph.EdgeEffectAllow})
	s.app.SecurityGraph.AddEdge(&graph.Edge{ID: "alice-admin-b", Source: "user:alice", Target: "bucket:prod-b", Kind: graph.EdgeKindCanAdmin, Effect: graph.EdgeEffectAllow})

	createA := do(t, s, http.MethodPost, "/api/v1/graph/access-reviews", map[string]any{
		"name":       "Review A",
		"created_by": "secops@example.com",
		"scope": map[string]any{
			"resources": []string{"bucket:prod-a"},
		},
	})
	if createA.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d body=%s", createA.Code, createA.Body.String())
	}
	reviewA := decodeJSON(t, createA)
	reviewAID := reviewA["id"].(string)
	itemAID := reviewA["items"].([]interface{})[0].(map[string]any)["id"].(string)

	createB := do(t, s, http.MethodPost, "/api/v1/graph/access-reviews", map[string]any{
		"name":       "Review B",
		"created_by": "secops@example.com",
		"scope": map[string]any{
			"resources": []string{"bucket:prod-b"},
		},
	})
	if createB.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d body=%s", createB.Code, createB.Body.String())
	}
	reviewB := decodeJSON(t, createB)
	reviewBID := reviewB["id"].(string)

	startA := do(t, s, http.MethodPost, "/api/v1/graph/access-reviews/"+reviewAID+"/start", nil)
	if startA.Code != http.StatusOK {
		t.Fatalf("expected 200 starting review A, got %d body=%s", startA.Code, startA.Body.String())
	}
	startB := do(t, s, http.MethodPost, "/api/v1/graph/access-reviews/"+reviewBID+"/start", nil)
	if startB.Code != http.StatusOK {
		t.Fatalf("expected 200 starting review B, got %d body=%s", startB.Code, startB.Body.String())
	}

	rec := do(t, s, http.MethodPost, "/api/v1/graph/access-reviews/"+reviewBID+"/items/"+itemAID+"/decision", map[string]any{
		"action":     "approve",
		"decided_by": "secops@example.com",
	})
	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for foreign review item decision, got %d body=%s", rec.Code, rec.Body.String())
	}

	storedA, ok := s.app.Identity.GetReview(context.Background(), reviewAID)
	if !ok {
		t.Fatalf("expected review A to exist")
	}
	if storedA.Items[0].Decision != nil {
		t.Fatalf("expected review A item to remain undecided")
	}
}
