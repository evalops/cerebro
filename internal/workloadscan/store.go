package workloadscan

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

type RunStore interface {
	SaveRun(ctx context.Context, run *RunRecord) error
	LoadRun(ctx context.Context, runID string) (*RunRecord, error)
	ListRuns(ctx context.Context, opts RunListOptions) ([]RunRecord, error)
	AppendEvent(ctx context.Context, runID string, event RunEvent) (RunEvent, error)
	LoadEvents(ctx context.Context, runID string) ([]RunEvent, error)
	Close() error
}

type SQLiteRunStore struct {
	db *sql.DB
}

func NewSQLiteRunStore(path string) (*SQLiteRunStore, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, fmt.Errorf("workload scan state path is required")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0750); err != nil {
		return nil, fmt.Errorf("create workload scan state directory: %w", err)
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open workload scan sqlite: %w", err)
	}
	if err := initSQLiteRunStore(db); err != nil {
		_ = db.Close()
		return nil, err
	}
	return &SQLiteRunStore{db: db}, nil
}

func initSQLiteRunStore(db *sql.DB) error {
	if db == nil {
		return fmt.Errorf("workload scan sqlite db is nil")
	}
	schema := `
	CREATE TABLE IF NOT EXISTS workload_scan_runs (
		run_id TEXT PRIMARY KEY,
		provider TEXT NOT NULL,
		status TEXT NOT NULL,
		stage TEXT NOT NULL,
		submitted_at TIMESTAMP NOT NULL,
		started_at TIMESTAMP,
		completed_at TIMESTAMP,
		updated_at TIMESTAMP NOT NULL,
		payload JSON NOT NULL
	);
	CREATE INDEX IF NOT EXISTS idx_workload_scan_runs_status_updated
		ON workload_scan_runs(status, updated_at DESC);
	CREATE TABLE IF NOT EXISTS workload_scan_events (
		run_id TEXT NOT NULL,
		sequence INTEGER NOT NULL,
		recorded_at TIMESTAMP NOT NULL,
		payload JSON NOT NULL,
		PRIMARY KEY (run_id, sequence)
	);
	`
	if _, err := db.ExecContext(context.Background(), schema); err != nil {
		return fmt.Errorf("init workload scan sqlite schema: %w", err)
	}
	return nil
}

func (s *SQLiteRunStore) SaveRun(ctx context.Context, run *RunRecord) error {
	if s == nil || s.db == nil || run == nil {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	run.UpdatedAt = run.UpdatedAt.UTC()
	payload, err := json.Marshal(run)
	if err != nil {
		return fmt.Errorf("encode workload scan run: %w", err)
	}
	_, err = s.db.ExecContext(ctx, `
		INSERT INTO workload_scan_runs (
			run_id, provider, status, stage, submitted_at, started_at, completed_at, updated_at, payload
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(run_id) DO UPDATE SET
			provider = excluded.provider,
			status = excluded.status,
			stage = excluded.stage,
			submitted_at = excluded.submitted_at,
			started_at = excluded.started_at,
			completed_at = excluded.completed_at,
			updated_at = excluded.updated_at,
			payload = excluded.payload
	`, run.ID, run.Provider, run.Status, run.Stage, run.SubmittedAt.UTC(), nullableTime(run.StartedAt), nullableTime(run.CompletedAt), run.UpdatedAt.UTC(), payload)
	if err != nil {
		return fmt.Errorf("persist workload scan run: %w", err)
	}
	return nil
}

func (s *SQLiteRunStore) LoadRun(ctx context.Context, runID string) (*RunRecord, error) {
	if s == nil || s.db == nil {
		return nil, nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	var payload []byte
	err := s.db.QueryRowContext(ctx, `SELECT payload FROM workload_scan_runs WHERE run_id = ?`, strings.TrimSpace(runID)).Scan(&payload)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("load workload scan run: %w", err)
	}
	var run RunRecord
	if err := json.Unmarshal(payload, &run); err != nil {
		return nil, fmt.Errorf("decode workload scan run: %w", err)
	}
	return &run, nil
}

func (s *SQLiteRunStore) ListRuns(ctx context.Context, opts RunListOptions) ([]RunRecord, error) {
	if s == nil || s.db == nil {
		return nil, nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	query := `SELECT payload FROM workload_scan_runs`
	clauses := make([]string, 0, 2)
	args := make([]any, 0, 8)
	if opts.ActiveOnly {
		clauses = append(clauses, `status NOT IN (?, ?)`)
		args = append(args, RunStatusSucceeded, RunStatusFailed)
	} else if len(opts.Statuses) > 0 {
		placeholders := make([]string, 0, len(opts.Statuses))
		for _, status := range opts.Statuses {
			placeholders = append(placeholders, "?")
			args = append(args, status)
		}
		// #nosec G202 -- the SQL fragment is built from fixed placeholders while values stay parameterized in args.
		clauses = append(clauses, `status IN (`+strings.Join(placeholders, ",")+`)`)
	}
	if len(clauses) > 0 {
		// #nosec G202 -- clause strings are fixed SQL literals assembled above; user-controlled values remain parameterized.
		query += ` WHERE ` + strings.Join(clauses, ` AND `)
	}
	query += ` ORDER BY updated_at DESC`
	if opts.Limit > 0 {
		query += ` LIMIT ?`
		args = append(args, opts.Limit)
	}
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("query workload scan runs: %w", err)
	}
	defer func() { _ = rows.Close() }()

	runs := make([]RunRecord, 0)
	for rows.Next() {
		var payload []byte
		if err := rows.Scan(&payload); err != nil {
			return nil, fmt.Errorf("scan workload scan run payload: %w", err)
		}
		var run RunRecord
		if err := json.Unmarshal(payload, &run); err != nil {
			return nil, fmt.Errorf("decode workload scan run payload: %w", err)
		}
		runs = append(runs, run)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate workload scan runs: %w", err)
	}
	return runs, nil
}

func (s *SQLiteRunStore) AppendEvent(ctx context.Context, runID string, event RunEvent) (RunEvent, error) {
	if s == nil || s.db == nil {
		return event, nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return event, fmt.Errorf("begin workload scan event tx: %w", err)
	}
	defer func() {
		_ = tx.Rollback()
	}()

	var nextSeq int64
	if err := tx.QueryRowContext(ctx, `SELECT COALESCE(MAX(sequence), 0) + 1 FROM workload_scan_events WHERE run_id = ?`, strings.TrimSpace(runID)).Scan(&nextSeq); err != nil {
		return event, fmt.Errorf("allocate workload scan event sequence: %w", err)
	}
	if event.RecordedAt.IsZero() {
		event.RecordedAt = time.Now().UTC()
	}
	event.Sequence = nextSeq
	payload, err := json.Marshal(event)
	if err != nil {
		return event, fmt.Errorf("encode workload scan event: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO workload_scan_events (run_id, sequence, recorded_at, payload)
		VALUES (?, ?, ?, ?)
	`, strings.TrimSpace(runID), event.Sequence, event.RecordedAt.UTC(), payload); err != nil {
		return event, fmt.Errorf("persist workload scan event: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return event, fmt.Errorf("commit workload scan event: %w", err)
	}
	return event, nil
}

func (s *SQLiteRunStore) LoadEvents(ctx context.Context, runID string) ([]RunEvent, error) {
	if s == nil || s.db == nil {
		return nil, nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT payload FROM workload_scan_events
		WHERE run_id = ?
		ORDER BY sequence ASC
	`, strings.TrimSpace(runID))
	if err != nil {
		return nil, fmt.Errorf("query workload scan events: %w", err)
	}
	defer func() { _ = rows.Close() }()

	events := make([]RunEvent, 0)
	for rows.Next() {
		var payload []byte
		if err := rows.Scan(&payload); err != nil {
			return nil, fmt.Errorf("scan workload scan event payload: %w", err)
		}
		var event RunEvent
		if err := json.Unmarshal(payload, &event); err != nil {
			return nil, fmt.Errorf("decode workload scan event payload: %w", err)
		}
		events = append(events, event)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate workload scan events: %w", err)
	}
	return events, nil
}

func (s *SQLiteRunStore) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

func nullableTime(ts *time.Time) any {
	if ts == nil || ts.IsZero() {
		return nil
	}
	return ts.UTC()
}
