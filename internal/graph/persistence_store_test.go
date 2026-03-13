package graph

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestGraphPersistenceStoreReplicatesAndRecoversFromFileReplica(t *testing.T) {
	localDir := t.TempDir()
	replicaDir := t.TempDir()

	store, err := NewGraphPersistenceStore(GraphPersistenceOptions{
		LocalPath:    localDir,
		MaxSnapshots: 4,
		ReplicaURI:   replicaDir,
	})
	if err != nil {
		t.Fatalf("new graph persistence store: %v", err)
	}

	g := New()
	g.AddNode(&Node{ID: "service:payments", Kind: NodeKindService, Name: "payments"})
	g.SetMetadata(Metadata{
		BuiltAt:       time.Date(2026, 3, 12, 22, 0, 0, 0, time.UTC),
		NodeCount:     1,
		EdgeCount:     0,
		Providers:     []string{"aws"},
		Accounts:      []string{"prod"},
		BuildDuration: 2 * time.Second,
	})

	record, err := store.SaveGraph(g)
	if err != nil {
		t.Fatalf("save graph snapshot: %v", err)
	}
	if record == nil || record.ID == "" {
		t.Fatalf("expected persisted snapshot record, got %#v", record)
	}

	status := store.Status()
	if status.LastReplicatedSnapshot != record.ID {
		t.Fatalf("expected last replicated snapshot %q, got %#v", record.ID, status)
	}

	if err := os.RemoveAll(localDir); err != nil {
		t.Fatalf("remove local snapshot dir: %v", err)
	}

	recoveredStore, err := NewGraphPersistenceStore(GraphPersistenceOptions{
		LocalPath:    localDir,
		MaxSnapshots: 4,
		ReplicaURI:   replicaDir,
	})
	if err != nil {
		t.Fatalf("new recovered graph persistence store: %v", err)
	}

	snapshot, recoveredRecord, source, err := recoveredStore.LoadLatestSnapshot()
	if err != nil {
		t.Fatalf("load latest snapshot from replica: %v", err)
	}
	if source != graphRecoverySourceReplica {
		t.Fatalf("expected replica recovery source, got %q", source)
	}
	if recoveredRecord == nil || recoveredRecord.ID != record.ID {
		t.Fatalf("expected recovered record %q, got %#v", record.ID, recoveredRecord)
	}
	if snapshot == nil || len(snapshot.Nodes) != 1 {
		t.Fatalf("expected one-node recovered snapshot, got %#v", snapshot)
	}

	records, err := recoveredStore.ListGraphSnapshotRecords()
	if err != nil {
		t.Fatalf("list graph snapshot records from replica: %v", err)
	}
	if len(records) != 1 || records[0].ID != record.ID {
		t.Fatalf("expected persisted record list to include %q, got %#v", record.ID, records)
	}

	replicaIndex := filepath.Join(replicaDir, "index.json")
	if _, err := os.Stat(replicaIndex); err != nil {
		t.Fatalf("expected replica index at %s: %v", replicaIndex, err)
	}
}
