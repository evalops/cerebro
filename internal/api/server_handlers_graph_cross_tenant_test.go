package api

import (
	"net/http"
	"testing"
	"time"
)

func TestGraphCrossTenantPatternEndpoints(t *testing.T) {
	s := newTestServer(t)
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

	buildA := do(t, s, http.MethodPost, "/api/v1/graph/cross-tenant/patterns/build", map[string]any{
		"tenant_id":   "tenant-alpha",
		"window_days": 365,
	})
	if buildA.Code != http.StatusOK {
		t.Fatalf("expected build samples 200, got %d: %s", buildA.Code, buildA.Body.String())
	}
	buildABody := decodeJSON(t, buildA)
	samplesA, ok := buildABody["samples"].([]any)
	if !ok || len(samplesA) == 0 {
		t.Fatalf("expected samples in build response, got %+v", buildABody["samples"])
	}

	buildB := do(t, s, http.MethodPost, "/api/v1/graph/cross-tenant/patterns/build", map[string]any{
		"tenant_id":   "tenant-beta",
		"window_days": 365,
	})
	if buildB.Code != http.StatusOK {
		t.Fatalf("expected build samples 200, got %d: %s", buildB.Code, buildB.Body.String())
	}
	buildBBody := decodeJSON(t, buildB)
	samplesB, ok := buildBBody["samples"].([]any)
	if !ok || len(samplesB) == 0 {
		t.Fatalf("expected samples in second build response, got %+v", buildBBody["samples"])
	}

	combinedSamples := append([]any{}, samplesA...)
	combinedSamples = append(combinedSamples, samplesB...)
	ingest := do(t, s, http.MethodPost, "/api/v1/graph/cross-tenant/patterns/ingest", map[string]any{
		"samples": combinedSamples,
	})
	if ingest.Code != http.StatusOK {
		t.Fatalf("expected ingest 200, got %d: %s", ingest.Code, ingest.Body.String())
	}
	ingestBody := decodeJSON(t, ingest)
	if received, ok := ingestBody["received"].(float64); !ok || received < float64(len(combinedSamples)) {
		t.Fatalf("expected ingest received count, got %+v", ingestBody)
	}

	list := do(t, s, http.MethodGet, "/api/v1/graph/cross-tenant/patterns?min_tenants=2", nil)
	if list.Code != http.StatusOK {
		t.Fatalf("expected list patterns 200, got %d: %s", list.Code, list.Body.String())
	}
	listBody := decodeJSON(t, list)
	if count, ok := listBody["count"].(float64); !ok || count < 1 {
		t.Fatalf("expected at least one pattern, got %+v", listBody)
	}

	matches := do(t, s, http.MethodGet, "/api/v1/graph/cross-tenant/matches?min_probability=0.5&limit=5", nil)
	if matches.Code != http.StatusOK {
		t.Fatalf("expected matches 200, got %d: %s", matches.Code, matches.Body.String())
	}
	matchesBody := decodeJSON(t, matches)
	if count, ok := matchesBody["count"].(float64); !ok || count < 1 {
		t.Fatalf("expected at least one match, got %+v", matchesBody)
	}
}

func TestGraphCrossTenantPatternEndpoints_InvalidQueries(t *testing.T) {
	s := newTestServer(t)
	seedGraphRiskFeedbackGraph(s.app.SecurityGraph)

	w := do(t, s, http.MethodGet, "/api/v1/graph/cross-tenant/matches?min_probability=2.0", nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid min_probability, got %d: %s", w.Code, w.Body.String())
	}

	w = do(t, s, http.MethodGet, "/api/v1/graph/cross-tenant/patterns?min_tenants=0", nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid min_tenants, got %d: %s", w.Code, w.Body.String())
	}
}
