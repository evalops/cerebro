package graph

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
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

func TestGraphPersistenceStoreSaveGraphReturnsRecordWhenReplicaSyncFails(t *testing.T) {
	localDir := t.TempDir()
	badReplicaBase := filepath.Join(t.TempDir(), "replica-file")
	if err := os.WriteFile(badReplicaBase, []byte("not a directory"), 0o600); err != nil {
		t.Fatalf("seed bad replica path: %v", err)
	}

	store, err := NewGraphPersistenceStore(GraphPersistenceOptions{
		LocalPath:    localDir,
		MaxSnapshots: 4,
		ReplicaURI:   badReplicaBase,
	})
	if err != nil {
		t.Fatalf("new graph persistence store: %v", err)
	}

	g := New()
	g.AddNode(&Node{ID: "service:billing", Kind: NodeKindService, Name: "billing"})
	g.SetMetadata(Metadata{
		BuiltAt:       time.Date(2026, 3, 12, 23, 0, 0, 0, time.UTC),
		NodeCount:     1,
		EdgeCount:     0,
		Providers:     []string{"aws"},
		Accounts:      []string{"prod"},
		BuildDuration: time.Second,
	})

	record, err := store.SaveGraph(g)
	if err == nil {
		t.Fatal("expected replica sync failure")
	}
	if record == nil || record.ID == "" {
		t.Fatalf("expected local persisted record despite replica failure, got %#v", record)
	}
	status := store.Status()
	if status.LastPersistedSnapshot != record.ID {
		t.Fatalf("expected persisted snapshot id %q in status, got %#v", record.ID, status)
	}
	if status.LastReplicationError == "" {
		t.Fatalf("expected replication error in status, got %#v", status)
	}
}

func TestGraphPersistenceStoreRejectsTraversalArtifactPathFromReplicaIndex(t *testing.T) {
	localDir := t.TempDir()
	replicaDir := t.TempDir()
	index := graphSnapshotIndex{
		APIVersion:  graphSnapshotIndexAPIVersion,
		GeneratedAt: time.Now().UTC(),
		Snapshots: []GraphSnapshotManifest{
			{
				APIVersion:   graphSnapshotManifestAPIVersion,
				Kind:         graphSnapshotManifestKind,
				SnapshotID:   "snap-1",
				ArtifactPath: "../escape.json.gz",
				Record: GraphSnapshotRecord{
					ID: "snap-1",
				},
			},
		},
	}
	payload, err := json.Marshal(index)
	if err != nil {
		t.Fatalf("marshal replica index: %v", err)
	}
	if err := os.WriteFile(filepath.Join(replicaDir, "index.json"), payload, 0o600); err != nil {
		t.Fatalf("write replica index: %v", err)
	}
	store, err := NewGraphPersistenceStore(GraphPersistenceOptions{
		LocalPath:    localDir,
		MaxSnapshots: 4,
		ReplicaURI:   replicaDir,
	})
	if err != nil {
		t.Fatalf("new graph persistence store: %v", err)
	}
	if _, err := store.ListGraphSnapshotRecords(); err == nil || !strings.Contains(err.Error(), "invalid replica snapshot artifact path") {
		t.Fatalf("expected invalid artifact path error, got %v", err)
	}
}

func TestFileGraphSnapshotReplicaRejectsTraversalKeys(t *testing.T) {
	replica := newFileGraphSnapshotReplica(t.TempDir())
	if err := replica.PutBytes(context.Background(), "../escape", []byte("payload"), "application/octet-stream"); err == nil {
		t.Fatal("expected traversal key rejection on put")
	}
	if _, err := replica.Open(context.Background(), "../escape"); err == nil {
		t.Fatal("expected traversal key rejection on open")
	}
	if err := replica.DeleteKeys(context.Background(), "../escape"); err == nil {
		t.Fatal("expected traversal key rejection on delete")
	}
}
