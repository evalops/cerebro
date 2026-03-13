package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/evalops/cerebro/internal/graph"
	"github.com/evalops/cerebro/internal/metrics"
	dto "github.com/prometheus/client_model/go"
)

func doWithTenantContext(t *testing.T, s *Server, method, path string, body any, tenantID string) *httptest.ResponseRecorder {
	t.Helper()
	var reader *bytes.Reader
	if body != nil {
		payload, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal body: %v", err)
		}
		reader = bytes.NewReader(payload)
	} else {
		reader = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, path, reader)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req = req.WithContext(context.WithValue(req.Context(), contextKeyTenant, tenantID))
	w := httptest.NewRecorder()
	s.ServeHTTP(w, req)
	return w
}

func TestGraphRiskHandlersUseTenantScopedGraph(t *testing.T) {
	s := newTestServer(t)
	g := s.app.SecurityGraph
	g.AddNode(&graph.Node{ID: "user:shared", Kind: graph.NodeKindUser, Name: "Shared User"})
	g.AddNode(&graph.Node{ID: "service:tenant-a", Kind: graph.NodeKindService, Name: "Tenant A", TenantID: "tenant-a"})
	g.AddNode(&graph.Node{ID: "service:tenant-b", Kind: graph.NodeKindService, Name: "Tenant B", TenantID: "tenant-b"})
	g.AddEdge(&graph.Edge{ID: "shared-a", Source: "user:shared", Target: "service:tenant-a", Kind: graph.EdgeKindCanRead, Effect: graph.EdgeEffectAllow})
	g.AddEdge(&graph.Edge{ID: "shared-b", Source: "user:shared", Target: "service:tenant-b", Kind: graph.EdgeKindCanRead, Effect: graph.EdgeEffectAllow})

	resp := doWithTenantContext(t, s, http.MethodGet, "/api/v1/graph/blast-radius/user:shared?max_depth=2", nil, "tenant-a")
	if resp.Code != http.StatusOK {
		t.Fatalf("expected tenant-scoped blast radius 200, got %d: %s", resp.Code, resp.Body.String())
	}
	body := decodeJSON(t, resp)
	reachable, ok := body["reachable_nodes"].([]any)
	if !ok || len(reachable) != 1 {
		t.Fatalf("expected one tenant-visible reachable node, got %#v", body["reachable_nodes"])
	}
	node := reachable[0].(map[string]any)["node"].(map[string]any)
	if node["id"] != "service:tenant-a" {
		t.Fatalf("expected tenant-a node only, got %#v", node)
	}
}

func TestGraphIntelligenceHandlersUseTenantScopedGraph(t *testing.T) {
	s := newTestServer(t)
	g := s.app.SecurityGraph
	base := time.Date(2026, 3, 12, 10, 0, 0, 0, time.UTC)
	g.AddNode(&graph.Node{ID: "service:tenant-a", Kind: graph.NodeKindService, Name: "Tenant A", TenantID: "tenant-a"})
	g.AddNode(&graph.Node{ID: "service:tenant-b", Kind: graph.NodeKindService, Name: "Tenant B", TenantID: "tenant-b"})
	g.AddNode(&graph.Node{
		ID:       "pull_request:tenant-b:42",
		Kind:     graph.NodeKindPullRequest,
		TenantID: "tenant-b",
		Properties: map[string]any{
			"repository":  "tenant-b",
			"number":      "42",
			"state":       "merged",
			"observed_at": base.Format(time.RFC3339),
			"valid_from":  base.Format(time.RFC3339),
		},
	})
	g.AddNode(&graph.Node{
		ID:       "deployment:tenant-b:deploy-1",
		Kind:     graph.NodeKindDeploymentRun,
		TenantID: "tenant-b",
		Properties: map[string]any{
			"deploy_id":   "deploy-1",
			"service_id":  "tenant-b",
			"environment": "prod",
			"status":      "succeeded",
			"observed_at": base.Add(5 * time.Minute).Format(time.RFC3339),
			"valid_from":  base.Add(5 * time.Minute).Format(time.RFC3339),
		},
	})
	g.AddNode(&graph.Node{
		ID:       "incident:tenant-b:1",
		Kind:     graph.NodeKindIncident,
		TenantID: "tenant-b",
		Properties: map[string]any{
			"incident_id": "incident-b-1",
			"service_id":  "tenant-b",
			"observed_at": base.Add(7 * time.Minute).Format(time.RFC3339),
			"valid_from":  base.Add(7 * time.Minute).Format(time.RFC3339),
		},
	})
	g.AddEdge(&graph.Edge{ID: "pr-b-service", Source: "pull_request:tenant-b:42", Target: "service:tenant-b", Kind: graph.EdgeKindTargets, Effect: graph.EdgeEffectAllow})
	g.AddEdge(&graph.Edge{ID: "deploy-b-service", Source: "deployment:tenant-b:deploy-1", Target: "service:tenant-b", Kind: graph.EdgeKindTargets, Effect: graph.EdgeEffectAllow})
	g.AddEdge(&graph.Edge{ID: "incident-b-service", Source: "incident:tenant-b:1", Target: "service:tenant-b", Kind: graph.EdgeKindTargets, Effect: graph.EdgeEffectAllow})
	graph.MaterializeEventCorrelations(g, base.Add(10*time.Minute))

	resp := doWithTenantContext(t, s, http.MethodGet, "/api/v1/platform/intelligence/event-correlations?event_id=incident:tenant-b:1&limit=10", nil, "tenant-a")
	if resp.Code != http.StatusNotFound {
		t.Fatalf("expected tenant-scoped event correlation lookup to hide foreign tenant event, got %d: %s", resp.Code, resp.Body.String())
	}
}

func TestCrossTenantReadOperationsEmitAuditAndMetrics(t *testing.T) {
	s := newTestServer(t)
	s.auditLogger = &captureAuditLogger{}
	seedGraphRiskFeedbackGraph(s.app.SecurityGraph)

	for i := 0; i < 5; i++ {
		w := do(t, s, http.MethodGet, "/api/v1/graph/risk-report", nil)
		if w.Code != http.StatusOK {
			t.Fatalf("expected risk report 200, got %d: %s", w.Code, w.Body.String())
		}
	}
	record := do(t, s, http.MethodPost, "/api/v1/graph/outcomes", map[string]any{
		"entity_id":   "customer:acme",
		"outcome":     "churn",
		"occurred_at": time.Now().UTC().Add(4 * time.Hour),
	})
	if record.Code != http.StatusOK {
		t.Fatalf("expected outcome record 200, got %d: %s", record.Code, record.Body.String())
	}

	build := doWithTenantContext(t, s, http.MethodPost, "/api/v1/graph/cross-tenant/patterns/build", map[string]any{
		"tenant_id":   "tenant-beta",
		"window_days": 365,
	}, "tenant-admin")
	if build.Code != http.StatusOK {
		t.Fatalf("expected build response 200, got %d: %s", build.Code, build.Body.String())
	}

	logger := s.auditLogger.(*captureAuditLogger)
	if len(logger.entries) != 1 {
		t.Fatalf("expected one cross-tenant audit entry, got %d", len(logger.entries))
	}
	entry := logger.entries[0]
	if entry.Action != "graph.cross_tenant.read" {
		t.Fatalf("expected cross-tenant audit action, got %#v", entry.Action)
	}
	if entry.Details["requesting_tenant"] != "tenant-admin" || entry.Details["target_tenant"] != "tenant-beta" {
		t.Fatalf("unexpected audit details: %#v", entry.Details)
	}

	metric := metrics.GraphCrossTenantReadsTotal.WithLabelValues("build_samples", "tenant-admin", "tenant-beta", "allowed")
	snapshot := &dto.Metric{}
	if err := metric.Write(snapshot); err != nil {
		t.Fatalf("read metric: %v", err)
	}
	if got := snapshot.GetCounter().GetValue(); got < 1 {
		t.Fatalf("expected cross-tenant metric increment, got %f", got)
	}
}
