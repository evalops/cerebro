package client

import (
	"context"
	"net/http"
	"net/url"
	"strconv"

	"github.com/evalops/cerebro/internal/policy"
)

type listPoliciesResponse struct {
	Policies []*policy.Policy `json:"policies"`
	Count    int              `json:"count"`
}

func (c *Client) ListPolicies(ctx context.Context, limit, offset int) ([]*policy.Policy, error) {
	query := url.Values{}
	if limit > 0 {
		query.Set("limit", strconv.Itoa(limit))
	}
	if offset > 0 {
		query.Set("offset", strconv.Itoa(offset))
	}

	var resp listPoliciesResponse
	if err := c.doJSON(ctx, http.MethodGet, "/api/v1/policies/", query, nil, &resp); err != nil {
		return nil, err
	}
	if resp.Policies == nil {
		return []*policy.Policy{}, nil
	}
	return resp.Policies, nil
}
