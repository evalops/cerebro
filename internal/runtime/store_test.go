package runtime

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func TestSQLiteIngestStoreSaveLoadRunAndEvents(t *testing.T) {
	store, err := NewSQLiteIngestStore(filepath.Join(t.TempDir(), "runtime-ingest.db"))
	if err != nil {
		t.Fatalf("NewSQLiteIngestStore: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	startedAt := time.Date(2026, 3, 15, 18, 0, 0, 0, time.UTC)
	run := &IngestRunRecord{
		ID:               "run-1",
		Source:           "kubernetes_audit",
		Status:           IngestRunStatusRunning,
		Stage:            "normalize",
		SubmittedAt:      startedAt,
		StartedAt:        &startedAt,
		UpdatedAt:        startedAt,
		ObservationCount: 12,
		FindingCount:     2,
		Metadata: map[string]string{
			"cluster": "prod-west",
		},
	}
	if err := store.SaveRun(context.Background(), run); err != nil {
		t.Fatalf("SaveRun: %v", err)
	}

	loaded, err := store.LoadRun(context.Background(), run.ID)
	if err != nil {
		t.Fatalf("LoadRun: %v", err)
	}
	if loaded == nil {
		t.Fatal("expected loaded run")
	}
	if loaded.Source != "kubernetes_audit" {
		t.Fatalf("source = %q, want %q", loaded.Source, "kubernetes_audit")
	}
	if loaded.ObservationCount != 12 {
		t.Fatalf("observation_count = %d, want 12", loaded.ObservationCount)
	}

	first, err := store.AppendEvent(context.Background(), run.ID, IngestEvent{
		Type:       "normalized",
		RecordedAt: startedAt.Add(time.Second),
		Data: map[string]any{
			"observations": 12,
		},
	})
	if err != nil {
		t.Fatalf("AppendEvent: %v", err)
	}
	if first.Sequence != 1 {
		t.Fatalf("first sequence = %d, want 1", first.Sequence)
	}

	second, err := store.AppendEvent(context.Background(), run.ID, IngestEvent{
		Type:       "detected",
		RecordedAt: startedAt.Add(2 * time.Second),
		Data: map[string]any{
			"findings": 2,
		},
	})
	if err != nil {
		t.Fatalf("AppendEvent second: %v", err)
	}
	if second.Sequence != 2 {
		t.Fatalf("second sequence = %d, want 2", second.Sequence)
	}

	events, err := store.LoadEvents(context.Background(), run.ID)
	if err != nil {
		t.Fatalf("LoadEvents: %v", err)
	}
	if len(events) != 2 {
		t.Fatalf("len(events) = %d, want 2", len(events))
	}
	if events[1].Type != "detected" {
		t.Fatalf("second event type = %q, want %q", events[1].Type, "detected")
	}
}

func TestSQLiteIngestStoreCheckpointPersistence(t *testing.T) {
	store, err := NewSQLiteIngestStore(filepath.Join(t.TempDir(), "runtime-ingest.db"))
	if err != nil {
		t.Fatalf("NewSQLiteIngestStore: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	now := time.Date(2026, 3, 15, 18, 0, 0, 0, time.UTC)
	run := &IngestRunRecord{
		ID:          "run-1",
		Source:      "tetragon",
		Status:      IngestRunStatusRunning,
		Stage:       "ingest",
		SubmittedAt: now,
		UpdatedAt:   now,
	}
	if err := store.SaveRun(context.Background(), run); err != nil {
		t.Fatalf("SaveRun: %v", err)
	}

	checkpoint, err := store.SaveCheckpoint(context.Background(), run.ID, IngestCheckpoint{
		Cursor:     "cursor-42",
		RecordedAt: now.Add(time.Minute),
		Metadata: map[string]string{
			"stream": "default",
		},
	})
	if err != nil {
		t.Fatalf("SaveCheckpoint: %v", err)
	}
	if checkpoint.Cursor != "cursor-42" {
		t.Fatalf("cursor = %q, want %q", checkpoint.Cursor, "cursor-42")
	}

	loaded, err := store.LoadCheckpoint(context.Background(), run.ID)
	if err != nil {
		t.Fatalf("LoadCheckpoint: %v", err)
	}
	if loaded == nil {
		t.Fatal("expected checkpoint")
	}
	if loaded.Metadata["stream"] != "default" {
		t.Fatalf("stream metadata = %q, want %q", loaded.Metadata["stream"], "default")
	}

	events, err := store.LoadEvents(context.Background(), run.ID)
	if err != nil {
		t.Fatalf("LoadEvents: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("len(events) = %d, want 1", len(events))
	}
	if events[0].Type != "checkpoint_saved" {
		t.Fatalf("event type = %q, want %q", events[0].Type, "checkpoint_saved")
	}
}

func TestSQLiteIngestStoreListRunsActiveOnly(t *testing.T) {
	store, err := NewSQLiteIngestStore(filepath.Join(t.TempDir(), "runtime-ingest.db"))
	if err != nil {
		t.Fatalf("NewSQLiteIngestStore: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	now := time.Date(2026, 3, 15, 18, 0, 0, 0, time.UTC)
	for _, run := range []*IngestRunRecord{
		{ID: "run-queued", Source: "kubernetes_audit", Status: IngestRunStatusQueued, Stage: "queued", SubmittedAt: now, UpdatedAt: now},
		{ID: "run-running", Source: "tetragon", Status: IngestRunStatusRunning, Stage: "normalize", SubmittedAt: now.Add(time.Minute), UpdatedAt: now.Add(time.Minute)},
		{ID: "run-completed", Source: "tetragon", Status: IngestRunStatusCompleted, Stage: "completed", SubmittedAt: now.Add(2 * time.Minute), UpdatedAt: now.Add(2 * time.Minute)},
	} {
		if err := store.SaveRun(context.Background(), run); err != nil {
			t.Fatalf("SaveRun(%s): %v", run.ID, err)
		}
	}

	active, err := store.ListRuns(context.Background(), IngestRunListOptions{
		ActiveOnly:         true,
		OrderBySubmittedAt: true,
	})
	if err != nil {
		t.Fatalf("ListRuns: %v", err)
	}
	if len(active) != 2 {
		t.Fatalf("len(active) = %d, want 2", len(active))
	}
	if active[0].ID != "run-running" || active[1].ID != "run-queued" {
		t.Fatalf("active runs = %#v", active)
	}
}
