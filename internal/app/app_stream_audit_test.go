package app

import (
	"testing"
	"time"

	"github.com/evalops/cerebro/internal/events"
)

func TestParseAuditMutationCloudEventUsesTableAwareResourceIDs(t *testing.T) {
	evt := events.CloudEvent{
		ID:     "evt-audit-multi-provider-1",
		Source: "urn:test:audit",
		Type:   "aws.cloudtrail.asset.changed",
		Time:   time.Date(2026, 3, 14, 12, 0, 0, 0, time.UTC),
		Data: map[string]any{
			"mutations": []any{
				map[string]any{
					"table_name": "aws_ec2_security_groups",
					"payload": map[string]any{
						"arn":      "arn:aws:ec2:us-east-1:123456789012:security-group/sg-123",
						"_cq_id":   "cq-sg-123",
						"group_id": "sg-123",
					},
				},
				map[string]any{
					"table_name": "gcp_compute_firewalls",
					"payload": map[string]any{
						"self_link": "https://compute.googleapis.com/projects/p1/global/firewalls/fw-1",
						"_cq_id":    "cq-fw-1",
						"id":        "1234567890",
					},
				},
				map[string]any{
					"table_name": "azure_network_security_groups",
					"payload": map[string]any{
						"id":     "/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.Network/networkSecurityGroups/nsg-1",
						"_cq_id": "cq-nsg-1",
						"name":   "nsg-1",
					},
				},
			},
		},
	}

	mutations, err := parseAuditMutationCloudEvent(evt)
	if err != nil {
		t.Fatalf("parseAuditMutationCloudEvent failed: %v", err)
	}
	if len(mutations) != 3 {
		t.Fatalf("expected 3 mutations, got %d", len(mutations))
	}

	if got := mutations[0].ResourceID; got != "arn:aws:ec2:us-east-1:123456789012:security-group/sg-123" {
		t.Fatalf("expected AWS resource ID to prefer arn, got %q", got)
	}
	if got := mutations[1].ResourceID; got != "https://compute.googleapis.com/projects/p1/global/firewalls/fw-1" {
		t.Fatalf("expected GCP resource ID to prefer self_link, got %q", got)
	}
	if got := mutations[2].ResourceID; got != "/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.Network/networkSecurityGroups/nsg-1" {
		t.Fatalf("expected Azure resource ID to prefer id, got %q", got)
	}
}
