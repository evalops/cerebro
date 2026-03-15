package runtime

import (
	"context"
	"testing"
	"time"
)

func TestObservationRoundTripPreservesDetectionFields(t *testing.T) {
	event := &RuntimeEvent{
		ID:           "event-1",
		Timestamp:    time.Date(2026, 3, 15, 20, 0, 0, 0, time.UTC),
		Source:       "agent-1",
		ResourceID:   "pod:prod/web",
		ResourceType: "pod",
		EventType:    "process",
		Process: &ProcessEvent{
			Name:       "xmrig",
			Cmdline:    "xmrig --url pool.example.com",
			ParentName: "bash",
		},
		Container: &ContainerEvent{
			ContainerID: "ctr-1",
			Namespace:   "prod",
			Image:       "ghcr.io/acme/web:1.2.3",
			ImageID:     "sha256:abc",
		},
		Metadata: map[string]any{
			"cluster":      "prod-west",
			"principal_id": "system:serviceaccount:prod:web",
			"trace_id":     "trace-1",
		},
	}

	observation := ObservationFromEvent(event)
	if observation == nil {
		t.Fatal("expected observation")
	}
	if observation.Kind != ObservationKindProcessExec {
		t.Fatalf("kind = %s, want %s", observation.Kind, ObservationKindProcessExec)
	}
	if observation.PrincipalID != "system:serviceaccount:prod:web" {
		t.Fatalf("principal_id = %q, want %q", observation.PrincipalID, "system:serviceaccount:prod:web")
	}

	roundTrip := observation.AsRuntimeEvent()
	if roundTrip == nil {
		t.Fatal("expected round-trip event")
	}
	if roundTrip.Process == nil || roundTrip.Process.Name != "xmrig" {
		t.Fatalf("round-trip process = %#v", roundTrip.Process)
	}
	if roundTrip.Metadata["cluster"] != "prod-west" {
		t.Fatalf("cluster metadata = %#v, want %q", roundTrip.Metadata["cluster"], "prod-west")
	}
}

func TestDetectionEngineProcessObservation(t *testing.T) {
	engine := NewDetectionEngine()
	observation := &RuntimeObservation{
		ID:         "obs-1",
		Kind:       ObservationKindProcessExec,
		Source:     "tetragon",
		ObservedAt: time.Now(),
		Process: &ProcessEvent{
			Name:    "xmrig",
			Cmdline: "xmrig --pool stratum://pool.example.com",
		},
		Container: &ContainerEvent{
			ContainerID: "ctr-1",
		},
	}

	findings := engine.ProcessObservation(context.Background(), observation)
	if len(findings) != 1 {
		t.Fatalf("len(findings) = %d, want 1", len(findings))
	}
	if findings[0].Observation == nil {
		t.Fatal("expected finding observation to be populated")
	}
	if findings[0].Event == nil || findings[0].Event.Process == nil {
		t.Fatalf("expected legacy event compatibility on finding, got %#v", findings[0].Event)
	}
}

func TestObservationFromResponseExecution(t *testing.T) {
	endTime := time.Date(2026, 3, 15, 21, 0, 0, 0, time.UTC)
	execution := &ResponseExecution{
		ID:           "exec-1",
		PolicyID:     "policy-1",
		PolicyName:   "Block suspicious egress",
		TriggerEvent: "finding-1",
		Status:       StatusCompleted,
		ResourceID:   "deployment:prod/web",
		ResourceType: "deployment",
		ApprovedBy:   "alice",
		EndTime:      &endTime,
	}
	action := &ActionExecution{
		Type:      ActionBlockIP,
		Status:    StatusCompleted,
		StartTime: endTime.Add(-5 * time.Second),
		EndTime:   &endTime,
		Output:    "blocked 203.0.113.10",
	}

	observation := ObservationFromResponseExecution(execution, action)
	if observation == nil {
		t.Fatal("expected observation")
	}
	if observation.Kind != ObservationKindResponseOutcome {
		t.Fatalf("kind = %s, want %s", observation.Kind, ObservationKindResponseOutcome)
	}
	if observation.Metadata["action_type"] != ActionBlockIP {
		t.Fatalf("action_type = %#v, want %s", observation.Metadata["action_type"], ActionBlockIP)
	}
	if observation.ResourceID != "deployment:prod/web" {
		t.Fatalf("resource_id = %q, want %q", observation.ResourceID, "deployment:prod/web")
	}
}
