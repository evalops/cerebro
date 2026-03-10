package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/evalops/cerebro/internal/graph"
)

type platformGraphDiffRequest struct {
	FromSnapshotID string `json:"from_snapshot_id"`
	ToSnapshotID   string `json:"to_snapshot_id"`
}

func (s *Server) createPlatformGraphDiff(w http.ResponseWriter, r *http.Request) {
	var req platformGraphDiffRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.error(w, http.StatusBadRequest, "invalid request body")
		return
	}
	diff, status, err := s.platformGraphSnapshotDiff(req.FromSnapshotID, req.ToSnapshotID)
	if err != nil {
		s.error(w, status, err.Error())
		return
	}
	s.json(w, http.StatusOK, diff)
}

func (s *Server) getPlatformGraphSnapshotAncestry(w http.ResponseWriter, r *http.Request) {
	snapshotID := strings.TrimSpace(chi.URLParam(r, "snapshot_id"))
	if snapshotID == "" {
		s.error(w, http.StatusBadRequest, "snapshot id required")
		return
	}
	collection := s.platformGraphSnapshotCollection()
	ancestry, ok := graph.GraphSnapshotAncestryFromCollection(collection, snapshotID)
	if !ok {
		s.error(w, http.StatusNotFound, "graph snapshot not found")
		return
	}
	s.json(w, http.StatusOK, ancestry)
}

func (s *Server) getPlatformGraphSnapshotDiff(w http.ResponseWriter, r *http.Request) {
	fromSnapshotID := strings.TrimSpace(chi.URLParam(r, "snapshot_id"))
	toSnapshotID := strings.TrimSpace(chi.URLParam(r, "other_snapshot_id"))
	diff, status, err := s.platformGraphSnapshotDiff(fromSnapshotID, toSnapshotID)
	if err != nil {
		s.error(w, status, err.Error())
		return
	}
	s.json(w, http.StatusOK, diff)
}

func (s *Server) platformGraphSnapshotDiff(fromSnapshotID, toSnapshotID string) (*graph.GraphSnapshotDiffRecord, int, error) {
	fromSnapshotID = strings.TrimSpace(fromSnapshotID)
	toSnapshotID = strings.TrimSpace(toSnapshotID)
	if fromSnapshotID == "" || toSnapshotID == "" {
		return nil, http.StatusBadRequest, fmt.Errorf("from_snapshot_id and to_snapshot_id are required")
	}
	records := s.platformGraphSnapshotRecords()
	fromRecord, ok := records[fromSnapshotID]
	if !ok {
		return nil, http.StatusNotFound, fmt.Errorf("graph snapshot not found: %s", fromSnapshotID)
	}
	toRecord, ok := records[toSnapshotID]
	if !ok {
		return nil, http.StatusNotFound, fmt.Errorf("graph snapshot not found: %s", toSnapshotID)
	}
	if !fromRecord.Diffable || !toRecord.Diffable {
		return nil, http.StatusConflict, fmt.Errorf("graph snapshot diffs require materialized snapshots")
	}
	store := s.platformGraphSnapshotStore()
	if store == nil {
		return nil, http.StatusNotFound, fmt.Errorf("graph snapshot store not configured")
	}
	snapshots, _, err := store.LoadSnapshotsByRecordIDs(fromSnapshotID, toSnapshotID)
	if err != nil {
		return nil, http.StatusNotFound, err
	}
	diff := graph.DiffSnapshots(snapshots[fromSnapshotID], snapshots[toSnapshotID])
	record := graph.BuildGraphSnapshotDiffRecord(*fromRecord, *toRecord, diff, time.Now().UTC())
	if record == nil {
		return nil, http.StatusInternalServerError, fmt.Errorf("failed to build graph snapshot diff")
	}
	return record, 0, nil
}

func (s *Server) platformGraphSnapshotStore() *graph.SnapshotStore {
	snapshotPath := strings.TrimSpace(os.Getenv("GRAPH_SNAPSHOT_PATH"))
	if snapshotPath == "" {
		snapshotPath = filepath.Join(".cerebro", "graph-snapshots")
	}
	return graph.NewSnapshotStore(snapshotPath, 10)
}

func (s *Server) platformGraphSnapshotRecords() map[string]*graph.GraphSnapshotRecord {
	collection := graph.GraphSnapshotCollectionSnapshot(s.app.SecurityGraph, s.platformReportRunSnapshotMap(), time.Now().UTC())
	records := make(map[string]*graph.GraphSnapshotRecord, collection.Count)
	for i := range collection.Snapshots {
		record := collection.Snapshots[i]
		copy := record
		records[record.ID] = &copy
	}
	store := s.platformGraphSnapshotStore()
	if store == nil {
		return records
	}
	persisted, err := store.ListGraphSnapshotRecords()
	if err != nil {
		return records
	}
	for i := range persisted {
		record := persisted[i]
		existing, ok := records[record.ID]
		if !ok {
			copy := record
			records[record.ID] = &copy
			continue
		}
		mergePlatformGraphSnapshotRecord(existing, record)
	}
	return records
}

func (s *Server) platformReportRunSnapshotMap() map[string]*graph.ReportRun {
	s.platformReportRunMu.RLock()
	defer s.platformReportRunMu.RUnlock()
	return s.clonePlatformReportRunsLocked()
}

func mergePlatformGraphSnapshotRecord(dst *graph.GraphSnapshotRecord, src graph.GraphSnapshotRecord) {
	if dst == nil {
		return
	}
	if dst.BuiltAt == nil && src.BuiltAt != nil {
		copy := src.BuiltAt.UTC()
		dst.BuiltAt = &copy
	}
	if dst.CapturedAt == nil && src.CapturedAt != nil {
		copy := src.CapturedAt.UTC()
		dst.CapturedAt = &copy
	}
	if src.Current {
		dst.Current = true
	}
	if src.Materialized {
		dst.Materialized = true
	}
	if src.Diffable {
		dst.Diffable = true
	}
	if dst.StorageClass == "" {
		dst.StorageClass = strings.TrimSpace(src.StorageClass)
	}
	if dst.ByteSize == 0 {
		dst.ByteSize = src.ByteSize
	}
	if dst.NodeCount == 0 {
		dst.NodeCount = src.NodeCount
	}
	if dst.EdgeCount == 0 {
		dst.EdgeCount = src.EdgeCount
	}
	if dst.BuildDurationMS == 0 {
		dst.BuildDurationMS = src.BuildDurationMS
	}
	if dst.GraphSchemaVersion == 0 {
		dst.GraphSchemaVersion = src.GraphSchemaVersion
	}
	if dst.OntologyContractVersion == "" {
		dst.OntologyContractVersion = strings.TrimSpace(src.OntologyContractVersion)
	}
	if len(dst.Providers) == 0 {
		dst.Providers = append([]string(nil), src.Providers...)
	}
	if len(dst.Accounts) == 0 {
		dst.Accounts = append([]string(nil), src.Accounts...)
	}
}
