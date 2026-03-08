package client

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestListPolicies_SendsPaginationAndParsesResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/policies/" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		if got := r.URL.Query().Get("limit"); got != "10" {
			t.Fatalf("expected limit query, got %q", got)
		}
		if got := r.URL.Query().Get("offset"); got != "5" {
			t.Fatalf("expected offset query, got %q", got)
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"policies": []map[string]interface{}{
				{
					"id":       "policy-1",
					"name":     "Policy 1",
					"severity": "high",
					"resource": "aws::s3::bucket",
				},
			},
			"count": 1,
		})
	}))
	defer server.Close()

	c, err := New(Config{BaseURL: server.URL})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}

	policies, err := c.ListPolicies(context.Background(), 10, 5)
	if err != nil {
		t.Fatalf("list policies: %v", err)
	}
	if len(policies) != 1 {
		t.Fatalf("expected one policy, got %d", len(policies))
	}
	if policies[0].ID != "policy-1" {
		t.Fatalf("unexpected policy ID: %s", policies[0].ID)
	}
}
