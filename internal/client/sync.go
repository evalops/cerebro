package client

import (
	"context"
	"net/http"
)

type RelationshipBackfillStats struct {
	Scanned int64 `json:"scanned"`
	Updated int64 `json:"updated"`
	Deleted int64 `json:"deleted"`
	Skipped int64 `json:"skipped"`
}

func (c *Client) BackfillRelationshipIDs(ctx context.Context, batchSize int) (*RelationshipBackfillStats, error) {
	var reqBody map[string]interface{}
	if batchSize > 0 {
		reqBody = map[string]interface{}{"batch_size": batchSize}
	}

	var resp RelationshipBackfillStats
	if err := c.doJSON(ctx, http.MethodPost, "/api/v1/sync/backfill-relationships", nil, reqBody, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}
