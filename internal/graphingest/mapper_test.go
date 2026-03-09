package graphingest

import (
	"strings"
	"testing"
	"time"

	"github.com/evalops/cerebro/internal/events"
	"github.com/evalops/cerebro/internal/graph"
)

func TestLoadDefaultConfig(t *testing.T) {
	config, err := LoadDefaultConfig()
	if err != nil {
		t.Fatalf("load default config failed: %v", err)
	}
	if len(config.Mappings) == 0 {
		t.Fatal("expected at least one mapping")
	}
}

func TestMapperApply_GithubPRMerged(t *testing.T) {
	config, err := LoadDefaultConfig()
	if err != nil {
		t.Fatalf("load default config failed: %v", err)
	}

	g := graph.New()
	g.AddNode(&graph.Node{
		ID:   "person:alice@example.com",
		Kind: graph.NodeKindPerson,
		Name: "Alice",
		Properties: map[string]any{
			"email": "alice@example.com",
		},
	})

	mapper, err := NewMapper(config, func(raw string, _ events.CloudEvent) string {
		raw = strings.ToLower(strings.TrimSpace(raw))
		if strings.Contains(raw, "@") {
			return "person:" + raw
		}
		return raw
	})
	if err != nil {
		t.Fatalf("new mapper failed: %v", err)
	}

	now := time.Date(2026, 3, 8, 22, 0, 0, 0, time.UTC)
	result, err := mapper.Apply(g, events.CloudEvent{
		ID:     "evt-pr-1",
		Type:   "ensemble.tap.github.pull_request.merged",
		Time:   now,
		Source: "urn:ensemble:tap",
		Data: map[string]any{
			"repository":      "payments-api",
			"number":          42,
			"title":           "Improve reconciliation retries",
			"merged_by":       "alice",
			"merged_by_email": "alice@example.com",
		},
	})
	if err != nil {
		t.Fatalf("mapper apply failed: %v", err)
	}
	if !result.Matched {
		t.Fatalf("expected mapping to match event, got %#v", result)
	}

	service, ok := g.GetNode("service:payments-api")
	if !ok || service == nil {
		t.Fatalf("expected service node to be created, got %#v", service)
	}
	if service.Kind != graph.NodeKindService {
		t.Fatalf("expected service node kind %q, got %q", graph.NodeKindService, service.Kind)
	}
	if observedAt := strings.TrimSpace(stringValue(service.Properties["observed_at"])); observedAt == "" {
		t.Fatalf("expected observed_at metadata on service node, got %#v", service.Properties)
	}

	outEdges := g.GetOutEdges("person:alice@example.com")
	foundContribution := false
	for _, edge := range outEdges {
		if edge == nil {
			continue
		}
		if edge.Kind == graph.EdgeKindInteractedWith && edge.Target == "service:payments-api" {
			foundContribution = true
			break
		}
	}
	if !foundContribution {
		t.Fatalf("expected person -> service interacted_with edge, got %#v", outEdges)
	}
}

func TestMapperApply_NoMatch(t *testing.T) {
	config, err := LoadDefaultConfig()
	if err != nil {
		t.Fatalf("load default config failed: %v", err)
	}
	mapper, err := NewMapper(config, nil)
	if err != nil {
		t.Fatalf("new mapper failed: %v", err)
	}

	result, err := mapper.Apply(graph.New(), events.CloudEvent{
		ID:     "evt-other-1",
		Type:   "ensemble.tap.unknown.unmapped",
		Time:   time.Now().UTC(),
		Source: "urn:ensemble:tap",
		Data:   map[string]any{"repository": "payments-api"},
	})
	if err != nil {
		t.Fatalf("mapper apply failed: %v", err)
	}
	if result.Matched {
		t.Fatalf("expected mapping not to match, got %#v", result)
	}
}

func TestMapperApply_SupportTicketUpdated(t *testing.T) {
	config, err := LoadDefaultConfig()
	if err != nil {
		t.Fatalf("load default config failed: %v", err)
	}
	g := graph.New()
	g.AddNode(&graph.Node{
		ID:   "person:agent@example.com",
		Kind: graph.NodeKindPerson,
		Name: "Agent",
		Properties: map[string]any{
			"email": "agent@example.com",
		},
	})

	mapper, err := NewMapper(config, func(raw string, _ events.CloudEvent) string {
		raw = strings.ToLower(strings.TrimSpace(raw))
		if strings.Contains(raw, "@") {
			return "person:" + raw
		}
		return raw
	})
	if err != nil {
		t.Fatalf("new mapper failed: %v", err)
	}

	now := time.Date(2026, 3, 9, 18, 0, 0, 0, time.UTC)
	result, err := mapper.Apply(g, events.CloudEvent{
		ID:     "evt-support-1",
		Type:   "ensemble.tap.support.ticket.updated",
		Time:   now,
		Source: "urn:ensemble:tap",
		Data: map[string]any{
			"ticket_id":   "12345",
			"subject":     "Payment failures",
			"status":      "open",
			"priority":    "high",
			"update_id":   "u-1",
			"update_type": "comment",
			"agent_email": "agent@example.com",
		},
	})
	if err != nil {
		t.Fatalf("mapper apply failed: %v", err)
	}
	if !result.Matched {
		t.Fatalf("expected mapping match, got %#v", result)
	}

	ticketNode, ok := g.GetNode("ticket:support:12345")
	if !ok || ticketNode == nil || ticketNode.Kind != graph.NodeKindTicket {
		t.Fatalf("expected support ticket node, got %#v", ticketNode)
	}
	assignmentFound := false
	for _, edge := range g.GetOutEdges("person:agent@example.com") {
		if edge == nil {
			continue
		}
		if edge.Kind == graph.EdgeKindAssignedTo && edge.Target == "ticket:support:12345" {
			assignmentFound = true
			break
		}
	}
	if !assignmentFound {
		t.Fatalf("expected assigned_to edge to support ticket, got %#v", g.GetOutEdges("person:agent@example.com"))
	}
}

func stringValue(value any) string {
	s, _ := value.(string)
	return s
}
