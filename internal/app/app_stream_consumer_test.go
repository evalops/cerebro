package app

import (
	"context"
	"testing"
	"time"

	"github.com/writer/cerebro/internal/events"
	"github.com/writer/cerebro/internal/graph"
)

func TestParseTapType(t *testing.T) {
	system, entity, action := parseTapType("ensemble.tap.stripe.customer.created")
	if system != "stripe" || entity != "customer" || action != "created" {
		t.Fatalf("unexpected parse result: system=%q entity=%q action=%q", system, entity, action)
	}
}

func TestDeriveComputedFields(t *testing.T) {
	now := time.Date(2026, 3, 6, 12, 0, 0, 0, time.UTC)

	hubspot := deriveComputedFields("hubspot", "deal", map[string]any{
		"properties": map[string]any{
			"last_activity_date": "2026-03-01T00:00:00Z",
		},
	}, nil, now)
	if _, ok := hubspot["days_since_last_activity"]; !ok {
		t.Fatal("expected days_since_last_activity for hubspot deal")
	}

	salesforce := deriveComputedFields("salesforce", "opportunity", map[string]any{
		"LastModifiedDate": "2026-02-20T00:00:00Z",
	}, map[string]any{"CloseDate": "2026-04-01"}, now)
	if _, ok := salesforce["days_since_last_modified"]; !ok {
		t.Fatal("expected days_since_last_modified for salesforce opportunity")
	}
	if got := toInt(salesforce["close_date_push_count"]); got < 1 {
		t.Fatalf("expected inferred close_date_push_count >= 1, got %d", got)
	}

	stripe := deriveComputedFields("stripe", "subscription", map[string]any{
		"trial_end": "2026-03-10T00:00:00Z",
	}, nil, now)
	if got := toInt(stripe["days_until_trial_end"]); got <= 0 {
		t.Fatalf("expected positive days_until_trial_end, got %d", got)
	}
}

func TestHandleTapCloudEvent_BuildsBusinessNodeAndEdge(t *testing.T) {
	a := &App{SecurityGraph: graph.New()}
	evt := events.CloudEvent{
		Type: "ensemble.tap.hubspot.contact.updated",
		Time: time.Date(2026, 3, 6, 12, 0, 0, 0, time.UTC),
		Data: map[string]interface{}{
			"entity_id": "contact-1",
			"snapshot": map[string]interface{}{
				"name":       "Alice",
				"company_id": "company-1",
			},
		},
	}

	if err := a.handleTapCloudEvent(context.Background(), evt); err != nil {
		t.Fatalf("handleTapCloudEvent failed: %v", err)
	}

	node, ok := a.SecurityGraph.GetNode("hubspot:contact:contact-1")
	if !ok {
		t.Fatal("expected contact node to be created")
	}
	if node.Kind != graph.NodeKindContact {
		t.Fatalf("expected contact node kind, got %q", node.Kind)
	}

	edges := a.SecurityGraph.GetOutEdges("hubspot:contact:contact-1")
	if len(edges) == 0 {
		t.Fatal("expected at least one relationship edge")
	}
	if edges[0].Kind != graph.EdgeKindWorksAt {
		t.Fatalf("expected edge kind %q, got %q", graph.EdgeKindWorksAt, edges[0].Kind)
	}
}
