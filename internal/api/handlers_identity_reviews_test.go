package api

import (
	"net/http"
	"testing"
	"time"

	"github.com/evalops/cerebro/internal/graph"
)

func TestIdentityReviewEndpointsRejectGraphCampaigns(t *testing.T) {
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
		ID:        "bucket:prod-data",
		Kind:      graph.NodeKindBucket,
		Name:      "prod-data",
		Provider:  "aws",
		Account:   "123456789012",
		Risk:      graph.RiskCritical,
		CreatedAt: now.Add(-500 * 24 * time.Hour),
	})
	s.app.SecurityGraph.AddEdge(&graph.Edge{ID: "alice-admin", Source: "user:alice", Target: "bucket:prod-data", Kind: graph.EdgeKindCanAdmin, Effect: graph.EdgeEffectAllow})

	create := do(t, s, http.MethodPost, "/api/v1/graph/access-reviews", map[string]any{
		"name":       "Graph Campaign",
		"created_by": "secops@example.com",
		"scope": map[string]any{
			"type":      "resource",
			"resources": []string{"bucket:prod-data"},
		},
	})
	if create.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d body=%s", create.Code, create.Body.String())
	}
	graphReview := decodeJSON(t, create)
	reviewID := graphReview["id"].(string)
	itemID := graphReview["items"].([]any)[0].(map[string]any)["id"].(string)

	list := do(t, s, http.MethodGet, "/api/v1/identity/reviews", nil)
	if list.Code != http.StatusOK {
		t.Fatalf("expected 200 listing identity reviews, got %d body=%s", list.Code, list.Body.String())
	}
	listBody := decodeJSON(t, list)
	if listBody["count"].(float64) != 0 {
		t.Fatalf("expected graph review to be hidden from identity list, got %#v", listBody)
	}

	get := do(t, s, http.MethodGet, "/api/v1/identity/reviews/"+reviewID, nil)
	if get.Code != http.StatusNotFound {
		t.Fatalf("expected 404 getting graph review via identity route, got %d body=%s", get.Code, get.Body.String())
	}

	start := do(t, s, http.MethodPost, "/api/v1/identity/reviews/"+reviewID+"/start", nil)
	if start.Code != http.StatusNotFound {
		t.Fatalf("expected 404 starting graph review via identity route, got %d body=%s", start.Code, start.Body.String())
	}

	addItem := do(t, s, http.MethodPost, "/api/v1/identity/reviews/"+reviewID+"/items", map[string]any{
		"type": "user",
		"principal": map[string]any{
			"id":       "user:bob",
			"type":     "user",
			"name":     "bob@example.com",
			"provider": "aws",
			"account":  "123456789012",
		},
	})
	if addItem.Code != http.StatusNotFound {
		t.Fatalf("expected 404 adding item to graph review via identity route, got %d body=%s", addItem.Code, addItem.Body.String())
	}

	decide := do(t, s, http.MethodPost, "/api/v1/identity/reviews/"+reviewID+"/items/"+itemID+"/decide", map[string]any{
		"action":   "approve",
		"reviewer": "iam@example.com",
	})
	if decide.Code != http.StatusNotFound {
		t.Fatalf("expected 404 deciding graph review item via identity route, got %d body=%s", decide.Code, decide.Body.String())
	}
}

func TestIdentityReviewCreateRemainsManual(t *testing.T) {
	s := newTestServer(t)

	create := do(t, s, http.MethodPost, "/api/v1/identity/reviews", map[string]any{
		"name":       "Manual identity review",
		"created_by": "iam@example.com",
		"scope": map[string]any{
			"mode":      "resource",
			"resources": []string{"bucket:prod-data"},
			"users":     []string{"user:alice"},
		},
	})
	if create.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d body=%s", create.Code, create.Body.String())
	}
	review := decodeJSON(t, create)
	if review["generation_source"] != "manual" {
		t.Fatalf("expected manual generation source, got %#v", review["generation_source"])
	}
	if items, ok := review["items"]; ok && items != nil {
		typedItems, ok := items.([]any)
		if !ok {
			t.Fatalf("expected items array, got %#v", items)
		}
		if len(typedItems) != 0 {
			t.Fatalf("expected manual identity create to avoid graph auto-generation, got %#v", typedItems)
		}
	}
}
