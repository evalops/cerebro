package graph

import (
	"testing"
	"time"
)

func TestGetEntityRecordAtTimeAndDiff(t *testing.T) {
	base := time.Date(2026, 3, 10, 9, 0, 0, 0, time.UTC)
	g := New()
	g.AddNode(&Node{
		ID:       "service:payments",
		Kind:     NodeKindService,
		Name:     "Payments",
		Provider: "aws",
		Properties: map[string]any{
			"status":           "degraded",
			"owner":            "team-payments",
			"observed_at":      base.Add(2 * time.Hour).Format(time.RFC3339),
			"valid_from":       base.Format(time.RFC3339),
			"recorded_at":      base.Format(time.RFC3339),
			"transaction_from": base.Format(time.RFC3339),
		},
	})
	node, ok := g.GetNode("service:payments")
	if !ok || node == nil {
		t.Fatal("expected seeded node")
	}
	node.PropertyHistory = map[string][]PropertySnapshot{
		"status": []PropertySnapshot{
			{Timestamp: base, Value: "healthy"},
			{Timestamp: base.Add(2 * time.Hour), Value: "degraded"},
		},
		"owner": []PropertySnapshot{
			{Timestamp: base.Add(2 * time.Hour), Value: "team-payments"},
		},
	}

	record, ok := GetEntityRecordAtTime(g, "service:payments", base.Add(30*time.Minute), base.Add(30*time.Minute))
	if !ok {
		t.Fatal("expected entity record at time")
	}
	if got := record.Entity.Properties["status"]; got != "healthy" {
		t.Fatalf("expected historical status healthy, got %#v", got)
	}
	if _, ok := record.Entity.Properties["owner"]; ok {
		t.Fatalf("did not expect owner before it existed, got %#v", record.Entity.Properties["owner"])
	}
	if !record.Reconstruction.PropertyHistoryApplied {
		t.Fatalf("expected property history reconstruction, got %+v", record.Reconstruction)
	}
	if record.Reconstruction.HistoricalCoreFields {
		t.Fatalf("expected core field reconstruction to remain false, got %+v", record.Reconstruction)
	}

	diff, ok := GetEntityTimeDiff(g, "service:payments", base, base.Add(3*time.Hour), base.Add(3*time.Hour))
	if !ok {
		t.Fatal("expected entity time diff")
	}
	if len(diff.ChangedKeys) < 2 {
		t.Fatalf("expected multiple changed keys, got %+v", diff)
	}
	foundStatus := false
	foundOwner := false
	for _, change := range diff.PropertyChanges {
		switch change.Key {
		case "status":
			foundStatus = true
			if change.Before != "healthy" || change.After != "degraded" {
				t.Fatalf("unexpected status diff: %+v", change)
			}
		case "owner":
			foundOwner = true
			if change.Before != nil || change.After != "team-payments" {
				t.Fatalf("unexpected owner diff: %+v", change)
			}
		}
	}
	if !foundStatus || !foundOwner {
		t.Fatalf("expected status and owner diffs, got %+v", diff.PropertyChanges)
	}
}
