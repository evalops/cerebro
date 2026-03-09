package app

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/evalops/cerebro/internal/graph"
	"github.com/evalops/cerebro/internal/health"
)

func TestEvaluateGraphOntologySLOStatus(t *testing.T) {
	thresholds := graphOntologySLOThresholds{
		FallbackWarn:        12,
		FallbackCritical:    25,
		SchemaValidWarn:     98,
		SchemaValidCritical: 92,
	}

	healthyStatus, _ := evaluateGraphOntologySLOStatus(graph.GraphOntologySLO{
		FallbackActivityPercent: 4,
		SchemaValidWritePercent: 99.5,
	}, thresholds)
	if healthyStatus != health.StatusHealthy {
		t.Fatalf("expected healthy status, got %s", healthyStatus)
	}

	degradedStatus, degradedMsg := evaluateGraphOntologySLOStatus(graph.GraphOntologySLO{
		FallbackActivityPercent: 15,
		SchemaValidWritePercent: 99.5,
	}, thresholds)
	if degradedStatus != health.StatusDegraded {
		t.Fatalf("expected degraded status, got %s", degradedStatus)
	}
	if !strings.Contains(degradedMsg, "fallback_activity_percent") {
		t.Fatalf("expected fallback degradation message, got %q", degradedMsg)
	}

	unhealthyStatus, unhealthyMsg := evaluateGraphOntologySLOStatus(graph.GraphOntologySLO{
		FallbackActivityPercent: 10,
		SchemaValidWritePercent: 90,
	}, thresholds)
	if unhealthyStatus != health.StatusUnhealthy {
		t.Fatalf("expected unhealthy status, got %s", unhealthyStatus)
	}
	if !strings.Contains(unhealthyMsg, "schema_valid_write_percent") {
		t.Fatalf("expected schema validity unhealthy message, got %q", unhealthyMsg)
	}
}

func TestGraphOntologySLOHealthCheck(t *testing.T) {
	g := graph.New()
	now := time.Date(2026, 3, 9, 10, 0, 0, 0, time.UTC)
	g.AddNode(&graph.Node{
		ID:   "activity:test",
		Kind: graph.NodeKindActivity,
		Name: "Legacy Activity",
		Properties: map[string]any{
			"source_system": "github",
			"observed_at":   now.Format(time.RFC3339),
			"valid_from":    now.Format(time.RFC3339),
		},
	})

	application := &App{
		Config: &Config{
			GraphOntologyFallbackWarnPct:        10,
			GraphOntologyFallbackCriticalPct:    50,
			GraphOntologySchemaValidWarnPct:     98,
			GraphOntologySchemaValidCriticalPct: 92,
		},
		SecurityGraph: g,
	}

	result := application.graphOntologySLOHealthCheck()(context.Background())
	if result.Status != health.StatusUnhealthy {
		t.Fatalf("expected unhealthy status from high fallback activity, got %s (%s)", result.Status, result.Message)
	}
	if !strings.Contains(result.Message, "fallback_activity_percent") {
		t.Fatalf("expected fallback issue in message, got %q", result.Message)
	}
}

func TestGraphOntologySLOHealthCheckWithoutGraph(t *testing.T) {
	application := &App{}
	result := application.graphOntologySLOHealthCheck()(context.Background())
	if result.Status != health.StatusUnknown {
		t.Fatalf("expected unknown when graph is missing, got %s", result.Status)
	}
}
