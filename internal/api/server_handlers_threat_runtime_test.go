package api

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/evalops/cerebro/internal/runtime"
)

type failingRuntimeIngestStore struct {
	saveRunErr error
}

func (s *failingRuntimeIngestStore) Close() error { return nil }

func (s *failingRuntimeIngestStore) SaveRun(context.Context, *runtime.IngestRunRecord) error {
	return s.saveRunErr
}

func (s *failingRuntimeIngestStore) LoadRun(context.Context, string) (*runtime.IngestRunRecord, error) {
	return nil, nil
}

func (s *failingRuntimeIngestStore) ListRuns(context.Context, runtime.IngestRunListOptions) ([]runtime.IngestRunRecord, error) {
	return nil, nil
}

func (s *failingRuntimeIngestStore) AppendEvent(context.Context, string, runtime.IngestEvent) (runtime.IngestEvent, error) {
	return runtime.IngestEvent{}, nil
}

func (s *failingRuntimeIngestStore) LoadEvents(context.Context, string) ([]runtime.IngestEvent, error) {
	return nil, nil
}

func (s *failingRuntimeIngestStore) SaveCheckpoint(context.Context, string, runtime.IngestCheckpoint) (runtime.IngestCheckpoint, error) {
	return runtime.IngestCheckpoint{}, nil
}

func (s *failingRuntimeIngestStore) LoadCheckpoint(context.Context, string) (*runtime.IngestCheckpoint, error) {
	return nil, nil
}

func TestIngestRuntimeEventPersistsIngestRun(t *testing.T) {
	a := newTestApp(t)
	s := NewServer(a)

	w := do(t, s, http.MethodPost, "/api/v1/runtime/events", map[string]any{
		"id":            "evt-1",
		"timestamp":     "2026-03-15T19:35:00Z",
		"source":        "tetragon",
		"resource_id":   "pod/default/miner-0",
		"resource_type": "pod",
		"event_type":    "process",
		"process": map[string]any{
			"pid":  4242,
			"name": "xmrig",
			"path": "/usr/bin/xmrig",
		},
		"container": map[string]any{
			"container_id": "container-1",
			"namespace":    "default",
			"pod_name":     "miner-0",
			"image":        "ghcr.io/acme/miner:latest",
		},
	})
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	body := decodeJSON(t, w)
	runID, ok := body["run_id"].(string)
	if !ok || runID == "" {
		t.Fatalf("expected run_id in response, got %#v", body["run_id"])
	}

	run, err := a.RuntimeIngest.LoadRun(context.Background(), runID)
	if err != nil {
		t.Fatalf("LoadRun: %v", err)
	}
	if run == nil {
		t.Fatal("expected persisted run")
	}
	if run.Source != "runtime_event" {
		t.Fatalf("source = %q, want runtime_event", run.Source)
	}
	if run.Status != runtime.IngestRunStatusCompleted {
		t.Fatalf("status = %q, want %q", run.Status, runtime.IngestRunStatusCompleted)
	}
	if run.ObservationCount != 1 {
		t.Fatalf("observation_count = %d, want 1", run.ObservationCount)
	}
	if run.FindingCount != 1 {
		t.Fatalf("finding_count = %d, want 1", run.FindingCount)
	}
	if run.LastCheckpoint == nil || run.LastCheckpoint.Cursor != "evt-1" {
		t.Fatalf("last checkpoint = %#v, want cursor evt-1", run.LastCheckpoint)
	}

	events, err := a.RuntimeIngest.LoadEvents(context.Background(), runID)
	if err != nil {
		t.Fatalf("LoadEvents: %v", err)
	}
	if len(events) != 4 {
		t.Fatalf("len(events) = %d, want 4", len(events))
	}
	if events[0].Type != "ingest_started" {
		t.Fatalf("events[0].Type = %q, want ingest_started", events[0].Type)
	}
	if events[1].Type != "observation_processed" {
		t.Fatalf("events[1].Type = %q, want observation_processed", events[1].Type)
	}
	if got := events[1].Data["finding_count"]; got != float64(1) && got != 1 {
		t.Fatalf("observation event finding_count = %#v, want 1", got)
	}
	if events[2].Type != "checkpoint_saved" {
		t.Fatalf("events[2].Type = %q, want checkpoint_saved", events[2].Type)
	}
	if events[3].Type != "ingest_completed" {
		t.Fatalf("events[3].Type = %q, want ingest_completed", events[3].Type)
	}
}

func TestTelemetryIngestPersistsRunMetadataAndCheckpoint(t *testing.T) {
	a := newTestApp(t)
	s := NewServer(a)

	w := do(t, s, http.MethodPost, "/api/v1/telemetry/ingest", map[string]any{
		"cluster":       "prod-west",
		"node":          "worker-7",
		"agent_version": "1.4.2",
		"events": []map[string]any{
			{
				"id":            "telemetry-1",
				"timestamp":     "2026-03-15T19:36:00Z",
				"source":        "runtime-agent",
				"resource_id":   "pod/default/api-0",
				"resource_type": "pod",
				"event_type":    "process",
				"process": map[string]any{
					"pid":  100,
					"name": "sh",
					"path": "/bin/sh",
				},
			},
			{
				"id":            "telemetry-2",
				"timestamp":     "2026-03-15T19:36:05Z",
				"source":        "runtime-agent",
				"resource_id":   "pod/default/api-0",
				"resource_type": "pod",
				"event_type":    "process",
				"process": map[string]any{
					"pid":  101,
					"name": "xmrig",
					"path": "/usr/bin/xmrig",
				},
			},
		},
	})
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	body := decodeJSON(t, w)
	runID, ok := body["run_id"].(string)
	if !ok || runID == "" {
		t.Fatalf("expected run_id in response, got %#v", body["run_id"])
	}

	run, err := a.RuntimeIngest.LoadRun(context.Background(), runID)
	if err != nil {
		t.Fatalf("LoadRun: %v", err)
	}
	if run == nil {
		t.Fatal("expected persisted run")
	}
	if run.Source != "telemetry" {
		t.Fatalf("source = %q, want telemetry", run.Source)
	}
	if run.Metadata["cluster"] != "prod-west" {
		t.Fatalf("cluster metadata = %q, want prod-west", run.Metadata["cluster"])
	}
	if run.Metadata["node"] != "worker-7" {
		t.Fatalf("node metadata = %q, want worker-7", run.Metadata["node"])
	}
	if run.Metadata["agent_version"] != "1.4.2" {
		t.Fatalf("agent_version metadata = %q, want 1.4.2", run.Metadata["agent_version"])
	}
	if run.ObservationCount != 2 {
		t.Fatalf("observation_count = %d, want 2", run.ObservationCount)
	}
	if run.FindingCount != 1 {
		t.Fatalf("finding_count = %d, want 1", run.FindingCount)
	}
	if run.LastCheckpoint == nil || run.LastCheckpoint.Cursor != "telemetry-2" {
		t.Fatalf("last checkpoint = %#v, want cursor telemetry-2", run.LastCheckpoint)
	}
	if run.LastCheckpoint.Metadata["cluster"] != "prod-west" {
		t.Fatalf("checkpoint cluster = %q, want prod-west", run.LastCheckpoint.Metadata["cluster"])
	}
	if run.LastCheckpoint.Metadata["processed_events"] != "2" {
		t.Fatalf("checkpoint processed_events = %q, want 2", run.LastCheckpoint.Metadata["processed_events"])
	}

	events, err := a.RuntimeIngest.LoadEvents(context.Background(), runID)
	if err != nil {
		t.Fatalf("LoadEvents: %v", err)
	}
	if len(events) != 5 {
		t.Fatalf("len(events) = %d, want 5", len(events))
	}
	if got := events[1].Data["cluster"]; got != "prod-west" {
		t.Fatalf("first observation cluster = %#v, want prod-west", got)
	}
	if got := events[1].Data["node_name"]; got != "worker-7" {
		t.Fatalf("first observation node_name = %#v, want worker-7", got)
	}
}

func TestIngestRuntimeEventReturns500WhenRunPersistenceFails(t *testing.T) {
	a := newTestApp(t)
	deps := newServerDependenciesFromApp(a)
	deps.RuntimeIngest = &failingRuntimeIngestStore{saveRunErr: errors.New("boom")}
	s := NewServerWithDependencies(deps)

	w := do(t, s, http.MethodPost, "/api/v1/runtime/events", map[string]any{
		"id":            "evt-err",
		"timestamp":     "2026-03-15T19:37:00Z",
		"source":        "tetragon",
		"resource_id":   "pod/default/api-0",
		"resource_type": "pod",
		"event_type":    "process",
		"process": map[string]any{
			"name": "sh",
			"path": "/bin/sh",
		},
	})
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d: %s", w.Code, w.Body.String())
	}
}
