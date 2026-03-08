package client

import (
	"context"
	"net/http"
	"strings"
)

type ScanTableResponse struct {
	Scanned    int64                    `json:"scanned"`
	Violations int64                    `json:"violations"`
	Duration   string                   `json:"duration"`
	Findings   []map[string]interface{} `json:"findings"`
}

func (c *Client) ScanFindings(ctx context.Context, table string, limit int) (*ScanTableResponse, error) {
	req := map[string]interface{}{
		"table": strings.TrimSpace(table),
	}
	if limit > 0 {
		req["limit"] = limit
	}

	var resp ScanTableResponse
	if err := c.doJSON(ctx, http.MethodPost, "/api/v1/findings/scan", nil, req, &resp); err != nil {
		return nil, err
	}
	if resp.Findings == nil {
		resp.Findings = []map[string]interface{}{}
	}
	return &resp, nil
}
