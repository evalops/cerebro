package executionstore

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

type ProcessedEventRecord struct {
	Namespace      string
	EventKey       string
	PayloadHash    string
	FirstSeenAt    time.Time
	LastSeenAt     time.Time
	ProcessedAt    time.Time
	ExpiresAt      time.Time
	DuplicateCount int
}

func (s *SQLiteStore) LookupProcessedEvent(ctx context.Context, namespace, eventKey string, observedAt time.Time, ttl time.Duration) (*ProcessedEventRecord, error) {
	if s == nil || s.db == nil {
		return nil, nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	namespace = strings.TrimSpace(namespace)
	eventKey = strings.TrimSpace(eventKey)
	if namespace == "" || eventKey == "" {
		return nil, fmt.Errorf("processed event namespace and key are required")
	}
	if observedAt.IsZero() {
		observedAt = time.Now().UTC()
	} else {
		observedAt = observedAt.UTC()
	}
	if ttl <= 0 {
		return nil, fmt.Errorf("processed event ttl must be > 0")
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin processed event lookup tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctx, `
		DELETE FROM processed_events
		WHERE namespace = ? AND expires_at <= ?
	`, namespace, observedAt); err != nil {
		return nil, fmt.Errorf("prune expired processed events: %w", err)
	}

	var record ProcessedEventRecord
	err = tx.QueryRowContext(ctx, `
		SELECT namespace, event_key, payload_hash, first_seen_at, last_seen_at, processed_at, expires_at, duplicate_count
		FROM processed_events
		WHERE namespace = ? AND event_key = ?
	`, namespace, eventKey).Scan(
		&record.Namespace,
		&record.EventKey,
		&record.PayloadHash,
		&record.FirstSeenAt,
		&record.LastSeenAt,
		&record.ProcessedAt,
		&record.ExpiresAt,
		&record.DuplicateCount,
	)
	if errors.Is(err, sql.ErrNoRows) {
		if err := tx.Commit(); err != nil {
			return nil, fmt.Errorf("commit processed event lookup: %w", err)
		}
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("load processed event: %w", err)
	}

	record.LastSeenAt = observedAt
	record.ExpiresAt = observedAt.Add(ttl)
	record.DuplicateCount++
	if _, err := tx.ExecContext(ctx, `
		UPDATE processed_events
		SET last_seen_at = ?, expires_at = ?, duplicate_count = ?
		WHERE namespace = ? AND event_key = ?
	`, record.LastSeenAt, record.ExpiresAt, record.DuplicateCount, record.Namespace, record.EventKey); err != nil {
		return nil, fmt.Errorf("touch processed event: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit processed event lookup: %w", err)
	}
	return &record, nil
}

func (s *SQLiteStore) RememberProcessedEvent(ctx context.Context, record ProcessedEventRecord, maxRecords int) error {
	if s == nil || s.db == nil {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	record.Namespace = strings.TrimSpace(record.Namespace)
	record.EventKey = strings.TrimSpace(record.EventKey)
	record.PayloadHash = strings.TrimSpace(record.PayloadHash)
	if record.Namespace == "" || record.EventKey == "" {
		return fmt.Errorf("processed event namespace and key are required")
	}
	if record.FirstSeenAt.IsZero() {
		record.FirstSeenAt = time.Now().UTC()
	} else {
		record.FirstSeenAt = record.FirstSeenAt.UTC()
	}
	if record.LastSeenAt.IsZero() {
		record.LastSeenAt = record.FirstSeenAt
	} else {
		record.LastSeenAt = record.LastSeenAt.UTC()
	}
	if record.ProcessedAt.IsZero() {
		record.ProcessedAt = record.LastSeenAt
	} else {
		record.ProcessedAt = record.ProcessedAt.UTC()
	}
	if record.ExpiresAt.IsZero() {
		record.ExpiresAt = record.ProcessedAt
	} else {
		record.ExpiresAt = record.ExpiresAt.UTC()
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin processed event remember tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctx, `
		DELETE FROM processed_events
		WHERE namespace = ? AND expires_at <= ?
	`, record.Namespace, record.ProcessedAt); err != nil {
		return fmt.Errorf("prune expired processed events: %w", err)
	}

	if _, err := tx.ExecContext(ctx, `
		INSERT INTO processed_events (
			namespace, event_key, payload_hash, first_seen_at, last_seen_at, processed_at, expires_at, duplicate_count
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(namespace, event_key) DO UPDATE SET
			payload_hash = excluded.payload_hash,
			last_seen_at = excluded.last_seen_at,
			processed_at = excluded.processed_at,
			expires_at = excluded.expires_at
	`, record.Namespace, record.EventKey, record.PayloadHash, record.FirstSeenAt, record.LastSeenAt, record.ProcessedAt, record.ExpiresAt, record.DuplicateCount); err != nil {
		return fmt.Errorf("persist processed event: %w", err)
	}

	if maxRecords > 0 {
		if _, err := tx.ExecContext(ctx, `
			DELETE FROM processed_events
			WHERE namespace = ?
			  AND event_key IN (
				SELECT event_key
				FROM processed_events
				WHERE namespace = ?
				ORDER BY processed_at DESC, event_key DESC
				LIMIT -1 OFFSET ?
			  )
		`, record.Namespace, record.Namespace, maxRecords); err != nil {
			return fmt.Errorf("trim processed events: %w", err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit processed event remember: %w", err)
	}
	return nil
}
