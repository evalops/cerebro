package api

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"

	nativesync "github.com/evalops/cerebro/internal/sync"
)

func (s *Server) backfillRelationshipIDs(w http.ResponseWriter, r *http.Request) {
	var req struct {
		BatchSize int `json:"batch_size"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil && !errors.Is(err, io.EOF) {
		s.error(w, http.StatusBadRequest, "invalid request")
		return
	}
	if req.BatchSize <= 0 {
		req.BatchSize = 200
	}

	if s.app.Snowflake == nil {
		s.error(w, http.StatusServiceUnavailable, "snowflake not configured")
		return
	}

	extractor := nativesync.NewRelationshipExtractor(s.app.Snowflake, s.app.Logger)
	stats, err := extractor.BackfillNormalizedRelationshipIDs(r.Context(), req.BatchSize)
	if err != nil {
		s.errorFromErr(w, err)
		return
	}

	s.json(w, http.StatusOK, map[string]interface{}{
		"scanned": stats.Scanned,
		"updated": stats.Updated,
		"deleted": stats.Deleted,
		"skipped": stats.Skipped,
	})
}
