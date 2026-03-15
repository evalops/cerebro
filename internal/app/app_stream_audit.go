package app

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/evalops/cerebro/internal/events"
	"github.com/evalops/cerebro/internal/graph/builders"
	"github.com/evalops/cerebro/internal/snowflake"
)

type auditMutationRecord struct {
	TableName  string
	ResourceID string
	ChangeType string
	Provider   string
	Region     string
	AccountID  string
	Payload    map[string]any
	EventID    string
	EventTime  time.Time
}

func isAuditMutationEventType(eventType string) bool {
	eventType = strings.ToLower(strings.TrimSpace(eventType))
	switch {
	case strings.HasPrefix(eventType, "aws.cloudtrail.asset."):
		return true
	case strings.HasPrefix(eventType, "gcp.auditlog.asset."),
		strings.HasPrefix(eventType, "gcp.auditlogs.asset."):
		return true
	case strings.HasPrefix(eventType, "azure.activitylog.asset."),
		strings.HasPrefix(eventType, "azure.activitylogs.asset."):
		return true
	default:
		return false
	}
}

func (a *App) handleAuditMutationCloudEvent(ctx context.Context, evt events.CloudEvent) error {
	if a == nil || a.Warehouse == nil {
		return nil
	}

	mutations, err := parseAuditMutationCloudEvent(evt)
	if err != nil {
		return err
	}
	if len(mutations) == 0 {
		return nil
	}

	cdcEvents := make([]snowflake.CDCEvent, 0, len(mutations))
	for _, mutation := range mutations {
		payloadHash := hashAuditMutationPayload(mutation.Payload)
		cdcEvents = append(cdcEvents, snowflake.CDCEvent{
			EventID:     mutation.EventID,
			TableName:   mutation.TableName,
			ResourceID:  mutation.ResourceID,
			ChangeType:  mutation.ChangeType,
			Provider:    mutation.Provider,
			Region:      mutation.Region,
			AccountID:   mutation.AccountID,
			Payload:     mutation.Payload,
			PayloadHash: payloadHash,
			EventTime:   mutation.EventTime,
		})
	}

	if err := a.Warehouse.InsertCDCEvents(ctx, cdcEvents); err != nil {
		return fmt.Errorf("insert audit mutation cdc events: %w", err)
	}
	if a.Logger != nil {
		a.Logger.Info("ingested audit mutation cloud event",
			"event_type", cloudEventType(evt),
			"source", strings.TrimSpace(evt.Source),
			"mutations", len(cdcEvents),
		)
	}

	if !a.isSecurityGraphReady() || a.SecurityGraphBuilder == nil {
		return nil
	}
	summary, applied, err := a.TryApplySecurityGraphChanges(ctx, "audit_event")
	if err != nil {
		return err
	}
	if applied && a.Logger != nil {
		a.Logger.Info("applied realtime audit mutation graph update",
			"events", summary.EventsProcessed,
			"nodes_added", summary.NodesAdded,
			"nodes_updated", summary.NodesUpdated,
			"nodes_removed", summary.NodesRemoved,
			"tables", summary.Tables,
		)
	}
	return nil
}

func (a *App) isSecurityGraphReady() bool {
	if a == nil || a.graphReady == nil {
		return true
	}
	select {
	case <-a.graphReady:
		return true
	default:
		return false
	}
}

func parseAuditMutationCloudEvent(evt events.CloudEvent) ([]auditMutationRecord, error) {
	eventType := cloudEventType(evt)
	if !isAuditMutationEventType(eventType) {
		return nil, nil
	}

	rawRecords := make([]map[string]any, 0, 4)
	if batch, ok := evt.Data["mutations"].([]any); ok {
		for _, item := range batch {
			record := mapFromAny(item)
			if len(record) == 0 {
				continue
			}
			rawRecords = append(rawRecords, record)
		}
	} else {
		rawRecords = append(rawRecords, evt.Data)
	}

	out := make([]auditMutationRecord, 0, len(rawRecords))
	for idx, raw := range rawRecords {
		tableName := strings.ToLower(strings.TrimSpace(anyToString(firstPresent(raw, "table_name", "table"))))
		if tableName == "" {
			return nil, fmt.Errorf("audit mutation event %q requires data.table_name", eventType)
		}

		changeType := strings.ToLower(strings.TrimSpace(anyToString(firstPresent(raw, "change_type", "action"))))
		if changeType == "" {
			changeType = auditChangeTypeFromEventType(eventType)
		}
		if changeType == "" {
			changeType = "modified"
		}

		payload := cloneAuditMutationPayload(mapFromAny(firstPresent(raw, "payload", "snapshot", "resource", "asset")))
		if len(payload) == 0 {
			payload = deriveAuditMutationPayload(raw)
		}

		resourceID := strings.TrimSpace(anyToString(firstPresent(raw, "resource_id", "id", "arn", "self_link")))
		if resourceID == "" {
			resourceID = cdcResourceIDFromPayload(tableName, payload)
		}
		if resourceID == "" && changeType != "removed" {
			return nil, fmt.Errorf("audit mutation event %q requires resource_id for table %s", eventType, tableName)
		}

		eventTime := evt.Time.UTC()
		if eventTime.IsZero() {
			eventTime = time.Now().UTC()
		}
		if parsed, ok := parseTimeValue(firstPresent(raw, "event_time", "observed_at", "occurred_at", "timestamp")); ok {
			eventTime = parsed.UTC()
		}

		mutationEventID := strings.TrimSpace(anyToString(firstPresent(raw, "event_id", "mutation_id")))
		if mutationEventID == "" {
			if strings.TrimSpace(evt.ID) == "" {
				mutationEventID = fmt.Sprintf("%s:%d", tableName, idx)
			} else if len(rawRecords) == 1 {
				mutationEventID = strings.TrimSpace(evt.ID)
			} else {
				mutationEventID = fmt.Sprintf("%s:%d", strings.TrimSpace(evt.ID), idx)
			}
		}

		provider := auditProviderForTable(tableName)
		if provider == "" {
			provider = auditProviderFromEventType(eventType)
		}

		accountID := strings.TrimSpace(anyToString(firstPresent(
			raw,
			"account_id", "project_id", "subscription_id",
			"account", "project", "subscription",
		)))
		if accountID == "" {
			accountID = strings.TrimSpace(anyToString(firstPresent(
				payload,
				"account_id", "project_id", "subscription_id",
				"account", "project", "subscription",
			)))
		}

		region := strings.TrimSpace(anyToString(firstPresent(raw, "region", "location", "zone")))
		if region == "" {
			region = strings.TrimSpace(anyToString(firstPresent(payload, "region", "location", "zone")))
		}

		out = append(out, auditMutationRecord{
			TableName:  tableName,
			ResourceID: resourceID,
			ChangeType: changeType,
			Provider:   provider,
			Region:     region,
			AccountID:  accountID,
			Payload:    payload,
			EventID:    mutationEventID,
			EventTime:  eventTime,
		})
	}
	return out, nil
}

func auditChangeTypeFromEventType(eventType string) string {
	parts := strings.Split(strings.ToLower(strings.TrimSpace(eventType)), ".")
	if len(parts) == 0 {
		return ""
	}
	switch parts[len(parts)-1] {
	case "created", "added":
		return "added"
	case "deleted", "removed":
		return "removed"
	case "changed", "updated", "modified":
		return "modified"
	default:
		return ""
	}
}

func auditProviderFromEventType(eventType string) string {
	eventType = strings.ToLower(strings.TrimSpace(eventType))
	switch {
	case strings.HasPrefix(eventType, "aws."):
		return "aws"
	case strings.HasPrefix(eventType, "gcp."):
		return "gcp"
	case strings.HasPrefix(eventType, "azure."):
		return "azure"
	default:
		return ""
	}
}

func auditProviderForTable(tableName string) string {
	tableName = strings.ToLower(strings.TrimSpace(tableName))
	switch {
	case strings.HasPrefix(tableName, "aws_"):
		return "aws"
	case strings.HasPrefix(tableName, "gcp_"):
		return "gcp"
	case strings.HasPrefix(tableName, "azure_"):
		return "azure"
	default:
		return ""
	}
}

func cdcResourceIDFromPayload(tableName string, payload map[string]any) string {
	return builders.CDCResourceIDForTable(tableName, payload)
}

func deriveAuditMutationPayload(raw map[string]any) map[string]any {
	if len(raw) == 0 {
		return nil
	}
	excluded := map[string]struct{}{
		"table_name":      {},
		"table":           {},
		"change_type":     {},
		"action":          {},
		"resource_id":     {},
		"event_id":        {},
		"mutation_id":     {},
		"event_time":      {},
		"observed_at":     {},
		"occurred_at":     {},
		"timestamp":       {},
		"account_id":      {},
		"project_id":      {},
		"subscription_id": {},
		"account":         {},
		"project":         {},
		"subscription":    {},
		"region":          {},
		"location":        {},
		"zone":            {},
		"payload":         {},
		"snapshot":        {},
		"resource":        {},
		"asset":           {},
		"mutations":       {},
	}
	payload := make(map[string]any, len(raw))
	for key, value := range raw {
		if _, skip := excluded[key]; skip {
			continue
		}
		payload[key] = value
	}
	if len(payload) == 0 {
		return nil
	}
	return payload
}

func hashAuditMutationPayload(payload map[string]any) string {
	if len(payload) == 0 {
		return ""
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:])
}

func cloneAuditMutationPayload(payload map[string]any) map[string]any {
	if len(payload) == 0 {
		return nil
	}
	cloned := make(map[string]any, len(payload))
	for key, value := range payload {
		cloned[key] = value
	}
	return cloned
}
