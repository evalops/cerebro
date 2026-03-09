package graph

import (
	"testing"
	"time"
)

func TestNormalizeWriteMetadata_Defaults(t *testing.T) {
	now := time.Date(2026, 3, 9, 12, 0, 0, 0, time.UTC)
	meta := NormalizeWriteMetadata(
		time.Time{},
		time.Time{},
		nil,
		"",
		"",
		0,
		WriteMetadataDefaults{
			Now:               now,
			SourceSystem:      "api",
			SourceEventPrefix: "api",
		},
	)

	if !meta.ObservedAt.Equal(now) {
		t.Fatalf("expected observed_at=%s, got %s", now, meta.ObservedAt)
	}
	if !meta.ValidFrom.Equal(now) {
		t.Fatalf("expected valid_from=%s, got %s", now, meta.ValidFrom)
	}
	if meta.SourceSystem != "api" {
		t.Fatalf("expected source_system=api, got %s", meta.SourceSystem)
	}
	if meta.SourceEventID == "" {
		t.Fatal("expected generated source_event_id")
	}
	if meta.Confidence != 0.80 {
		t.Fatalf("expected confidence=0.80, got %.2f", meta.Confidence)
	}
}

func TestNormalizeWriteMetadata_ExplicitValuesAndPropertyMap(t *testing.T) {
	observed := time.Date(2026, 3, 8, 8, 30, 0, 0, time.UTC)
	validFrom := observed.Add(-15 * time.Minute)
	validTo := observed.Add(2 * time.Hour)

	meta := NormalizeWriteMetadata(
		observed,
		validFrom,
		&validTo,
		"Conductor",
		"evt-123",
		1.5,
		WriteMetadataDefaults{},
	)
	if meta.SourceSystem != "conductor" {
		t.Fatalf("expected normalized source_system, got %s", meta.SourceSystem)
	}
	if meta.Confidence != 1 {
		t.Fatalf("expected clamped confidence=1.0, got %.2f", meta.Confidence)
	}

	properties := map[string]any{
		"existing": "value",
	}
	meta.ApplyTo(properties)
	if properties["source_system"] != "conductor" {
		t.Fatalf("expected source_system in properties, got %#v", properties["source_system"])
	}
	if _, ok := properties["valid_to"]; !ok {
		t.Fatalf("expected valid_to in properties, got %#v", properties)
	}
	if properties["existing"] != "value" {
		t.Fatalf("expected existing properties to remain untouched, got %#v", properties)
	}
}
