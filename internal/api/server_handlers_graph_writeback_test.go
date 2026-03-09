package api

import (
	"net/http"
	"testing"

	"github.com/evalops/cerebro/internal/graph"
)

func TestGraphWriteObservationAndAnnotation(t *testing.T) {
	s := newTestServer(t)
	g := s.app.SecurityGraph
	g.AddNode(&graph.Node{
		ID:   "service:payments",
		Kind: graph.NodeKindService,
		Name: "Payments",
		Properties: map[string]any{
			"service_id":  "payments",
			"observed_at": "2026-03-08T00:00:00Z",
			"valid_from":  "2026-03-08T00:00:00Z",
		},
	})

	observation := do(t, s, http.MethodPost, "/api/v1/graph/write/observation", map[string]any{
		"entity_id":     "service:payments",
		"observation":   "deploy_risk_increase",
		"summary":       "Error rates spiked after deploy",
		"source_system": "composer",
	})
	if observation.Code != http.StatusCreated {
		t.Fatalf("expected 201 for observation, got %d: %s", observation.Code, observation.Body.String())
	}
	observationBody := decodeJSON(t, observation)
	observationID, _ := observationBody["observation_id"].(string)
	if observationID == "" {
		t.Fatalf("expected observation_id, got %+v", observationBody)
	}
	observationNode, ok := g.GetNode(observationID)
	if !ok || observationNode == nil {
		t.Fatalf("expected observation node %q to exist", observationID)
	}
	if observationNode.Kind != graph.NodeKindEvidence {
		t.Fatalf("expected observation node kind evidence, got %q", observationNode.Kind)
	}

	annotation := do(t, s, http.MethodPost, "/api/v1/graph/write/annotation", map[string]any{
		"entity_id":     "service:payments",
		"annotation":    "Rollback candidate if p95 latency continues climbing",
		"tags":          []string{"incident", "latency"},
		"source_system": "analyst",
	})
	if annotation.Code != http.StatusCreated {
		t.Fatalf("expected 201 for annotation, got %d: %s", annotation.Code, annotation.Body.String())
	}
	annotatedNode, ok := g.GetNode("service:payments")
	if !ok || annotatedNode == nil {
		t.Fatal("expected annotated node")
	}
	annotations, ok := annotatedNode.Properties["annotations"].([]map[string]any)
	if ok && len(annotations) > 0 {
		return
	}
	if raw, ok := annotatedNode.Properties["annotations"].([]any); !ok || len(raw) == 0 {
		t.Fatalf("expected annotations on entity, got %#v", annotatedNode.Properties["annotations"])
	}
}

func TestGraphWriteDecisionOutcomeAndIdentity(t *testing.T) {
	s := newTestServer(t)
	g := s.app.SecurityGraph

	g.AddNode(&graph.Node{
		ID:   "service:payments",
		Kind: graph.NodeKindService,
		Name: "Payments",
		Properties: map[string]any{
			"service_id":  "payments",
			"observed_at": "2026-03-08T00:00:00Z",
			"valid_from":  "2026-03-08T00:00:00Z",
		},
	})
	g.AddNode(&graph.Node{
		ID:   "person:alice@example.com",
		Kind: graph.NodeKindPerson,
		Name: "Alice",
		Properties: map[string]any{
			"email": "alice@example.com",
		},
	})

	resolve := do(t, s, http.MethodPost, "/api/v1/graph/identity/resolve", map[string]any{
		"source_system": "github",
		"external_id":   "alice-handle",
		"email":         "alice@example.com",
		"name":          "Alice",
	})
	if resolve.Code != http.StatusOK {
		t.Fatalf("expected 200 for identity resolve, got %d: %s", resolve.Code, resolve.Body.String())
	}
	resolveBody := decodeJSON(t, resolve)
	aliasID, _ := resolveBody["alias_node_id"].(string)
	if aliasID == "" {
		t.Fatalf("expected alias_node_id from identity resolve, got %+v", resolveBody)
	}

	decision := do(t, s, http.MethodPost, "/api/v1/graph/write/decision", map[string]any{
		"decision_type": "rollback",
		"status":        "approved",
		"made_by":       "person:alice@example.com",
		"rationale":     "Error budget burn rate exceeded threshold",
		"target_ids":    []string{"service:payments"},
		"source_system": "conductor",
	})
	if decision.Code != http.StatusCreated {
		t.Fatalf("expected 201 for decision, got %d: %s", decision.Code, decision.Body.String())
	}
	decisionBody := decodeJSON(t, decision)
	decisionID, _ := decisionBody["decision_id"].(string)
	if decisionID == "" {
		t.Fatalf("expected decision_id, got %+v", decisionBody)
	}
	if node, ok := g.GetNode(decisionID); !ok || node == nil || node.Kind != graph.NodeKindDecision {
		t.Fatalf("expected decision node %q to exist, got %#v", decisionID, node)
	}

	outcome := do(t, s, http.MethodPost, "/api/v1/graph/write/outcome", map[string]any{
		"decision_id":   decisionID,
		"outcome_type":  "deployment_result",
		"verdict":       "positive",
		"impact_score":  0.7,
		"target_ids":    []string{"service:payments"},
		"source_system": "conductor",
	})
	if outcome.Code != http.StatusCreated {
		t.Fatalf("expected 201 for outcome, got %d: %s", outcome.Code, outcome.Body.String())
	}
	outcomeBody := decodeJSON(t, outcome)
	outcomeID, _ := outcomeBody["outcome_id"].(string)
	if outcomeID == "" {
		t.Fatalf("expected outcome_id, got %+v", outcomeBody)
	}
	if node, ok := g.GetNode(outcomeID); !ok || node == nil || node.Kind != graph.NodeKindOutcome {
		t.Fatalf("expected outcome node %q to exist, got %#v", outcomeID, node)
	}

	split := do(t, s, http.MethodPost, "/api/v1/graph/identity/split", map[string]any{
		"alias_node_id":     aliasID,
		"canonical_node_id": "person:alice@example.com",
		"reason":            "manual correction",
		"source_system":     "analyst",
	})
	if split.Code != http.StatusOK {
		t.Fatalf("expected 200 for identity split, got %d: %s", split.Code, split.Body.String())
	}
	splitBody := decodeJSON(t, split)
	if removed, ok := splitBody["removed"].(bool); !ok || !removed {
		t.Fatalf("expected removed=true for identity split, got %+v", splitBody)
	}
}

func TestGraphWritebackValidationFailures(t *testing.T) {
	s := newTestServer(t)
	g := s.app.SecurityGraph

	g.AddNode(&graph.Node{
		ID:   "service:payments",
		Kind: graph.NodeKindService,
		Name: "Payments",
		Properties: map[string]any{
			"service_id":  "payments",
			"observed_at": "2026-03-08T00:00:00Z",
			"valid_from":  "2026-03-08T00:00:00Z",
		},
	})

	observation := do(t, s, http.MethodPost, "/api/v1/graph/write/observation", map[string]any{
		"observation": "deploy_risk_increase",
	})
	if observation.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for missing entity_id, got %d: %s", observation.Code, observation.Body.String())
	}

	decision := do(t, s, http.MethodPost, "/api/v1/graph/write/decision", map[string]any{
		"decision_type": "rollback",
		"target_ids":    []string{"service:missing"},
	})
	if decision.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for missing decision target, got %d: %s", decision.Code, decision.Body.String())
	}

	outcome := do(t, s, http.MethodPost, "/api/v1/graph/write/outcome", map[string]any{
		"decision_id":  "decision:missing",
		"outcome_type": "deployment_result",
		"verdict":      "positive",
	})
	if outcome.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for missing decision on outcome, got %d: %s", outcome.Code, outcome.Body.String())
	}

	resolve := do(t, s, http.MethodPost, "/api/v1/graph/identity/resolve", map[string]any{
		"external_id": "alice-handle",
	})
	if resolve.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for missing source_system on identity resolve, got %d: %s", resolve.Code, resolve.Body.String())
	}

	split := do(t, s, http.MethodPost, "/api/v1/graph/identity/split", map[string]any{
		"alias_node_id": "alias:github:alice-handle",
	})
	if split.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for missing canonical_node_id on identity split, got %d: %s", split.Code, split.Body.String())
	}
}
