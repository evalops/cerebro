package graph

import (
	"reflect"
	"sort"
	"time"
)

// EntityTimeReconstruction describes what portion of an entity was reconstructed from temporal history.
type EntityTimeReconstruction struct {
	AsOf                    time.Time `json:"as_of"`
	RecordedAt              time.Time `json:"recorded_at"`
	PropertyHistoryApplied  bool      `json:"property_history_applied"`
	HistoricalCoreFields    bool      `json:"historical_core_fields"`
	ReconstructedProperties int       `json:"reconstructed_properties"`
}

// EntityTimeRecord is the point-in-time entity read model.
type EntityTimeRecord struct {
	Entity         EntityRecord             `json:"entity"`
	Reconstruction EntityTimeReconstruction `json:"reconstruction"`
}

// EntityPropertyDiff captures one property change between two reconstructed entity states.
type EntityPropertyDiff struct {
	Key    string `json:"key"`
	Before any    `json:"before,omitempty"`
	After  any    `json:"after,omitempty"`
}

// EntityTimeDiffRecord captures one entity diff across two timestamps.
type EntityTimeDiffRecord struct {
	EntityID        string               `json:"entity_id"`
	From            time.Time            `json:"from"`
	To              time.Time            `json:"to"`
	RecordedAt      time.Time            `json:"recorded_at"`
	Before          EntityTimeRecord     `json:"before"`
	After           EntityTimeRecord     `json:"after"`
	ChangedKeys     []string             `json:"changed_keys,omitempty"`
	PropertyChanges []EntityPropertyDiff `json:"property_changes,omitempty"`
}

// GetEntityRecordAtTime reconstructs one entity at the requested valid-time slice.
func GetEntityRecordAtTime(g *Graph, id string, asOf, recordedAt time.Time) (EntityTimeRecord, bool) {
	if g == nil {
		return EntityTimeRecord{}, false
	}
	node, reconstruction, ok := g.EntityAtTime(id, asOf, recordedAt)
	if !ok {
		return EntityTimeRecord{}, false
	}
	record := buildEntityRecord(g, node, reconstruction.AsOf, reconstruction.RecordedAt, true)
	return EntityTimeRecord{
		Entity:         record,
		Reconstruction: reconstruction,
	}, true
}

// GetEntityTimeDiff compares one entity across two valid-time points.
func GetEntityTimeDiff(g *Graph, id string, from, to, recordedAt time.Time) (EntityTimeDiffRecord, bool) {
	before, ok := GetEntityRecordAtTime(g, id, from, recordedAt)
	if !ok {
		return EntityTimeDiffRecord{}, false
	}
	after, ok := GetEntityRecordAtTime(g, id, to, recordedAt)
	if !ok {
		return EntityTimeDiffRecord{}, false
	}
	changes := diffEntityProperties(before.Entity.Properties, after.Entity.Properties)
	changedKeys := make([]string, 0, len(changes))
	for _, change := range changes {
		changedKeys = append(changedKeys, change.Key)
	}
	if before.Entity.Kind != after.Entity.Kind {
		changedKeys = append(changedKeys, "kind")
	}
	if before.Entity.Name != after.Entity.Name {
		changedKeys = append(changedKeys, "name")
	}
	if before.Entity.Provider != after.Entity.Provider {
		changedKeys = append(changedKeys, "provider")
	}
	if before.Entity.Account != after.Entity.Account {
		changedKeys = append(changedKeys, "account")
	}
	if before.Entity.Region != after.Entity.Region {
		changedKeys = append(changedKeys, "region")
	}
	sort.Strings(changedKeys)
	return EntityTimeDiffRecord{
		EntityID:        id,
		From:            before.Reconstruction.AsOf,
		To:              after.Reconstruction.AsOf,
		RecordedAt:      before.Reconstruction.RecordedAt,
		Before:          before,
		After:           after,
		ChangedKeys:     changedKeys,
		PropertyChanges: changes,
	}, true
}

// EntityAtTime reconstructs one node's property state at one valid-time slice.
func (g *Graph) EntityAtTime(id string, asOf, recordedAt time.Time) (*Node, EntityTimeReconstruction, bool) {
	if g == nil {
		return nil, EntityTimeReconstruction{}, false
	}
	if asOf.IsZero() {
		asOf = temporalNowUTC()
	}
	if recordedAt.IsZero() {
		recordedAt = temporalNowUTC()
	}
	asOf = asOf.UTC()
	recordedAt = recordedAt.UTC()

	g.mu.RLock()
	defer g.mu.RUnlock()

	node, ok := g.nodes[id]
	if !ok || node == nil || !entityQueryAllowedNodeKind(node.Kind) || !g.nodeVisibleAtLocked(node, asOf, recordedAt) {
		return nil, EntityTimeReconstruction{}, false
	}

	reconstructed := cloneNode(node)
	reconstructed.Properties = reconstructNodePropertiesAt(node, asOf)
	if len(reconstructed.Properties) == 0 {
		reconstructed.Properties = nil
	}
	return reconstructed, EntityTimeReconstruction{
		AsOf:                    asOf,
		RecordedAt:              recordedAt,
		PropertyHistoryApplied:  len(node.PropertyHistory) > 0,
		HistoricalCoreFields:    false,
		ReconstructedProperties: len(reconstructed.Properties),
	}, true
}

func reconstructNodePropertiesAt(node *Node, asOf time.Time) map[string]any {
	if node == nil {
		return nil
	}
	keys := make(map[string]struct{}, len(node.Properties)+len(node.PropertyHistory))
	for key := range node.Properties {
		keys[key] = struct{}{}
	}
	for key := range node.PropertyHistory {
		keys[key] = struct{}{}
	}
	if len(keys) == 0 {
		return nil
	}

	properties := make(map[string]any, len(keys))
	for key := range keys {
		if value, ok := propertyValueAt(node, key, asOf); ok {
			properties[key] = cloneAny(value)
		}
	}
	return properties
}

func propertyValueAt(node *Node, key string, asOf time.Time) (any, bool) {
	if node == nil {
		return nil, false
	}
	if history := node.PropertyHistory[key]; len(history) > 0 {
		for i := len(history) - 1; i >= 0; i-- {
			if !history[i].Timestamp.After(asOf) {
				return history[i].Value, true
			}
		}
		return nil, false
	}
	value, ok := node.Properties[key]
	return value, ok
}

func diffEntityProperties(before, after map[string]any) []EntityPropertyDiff {
	keys := make(map[string]struct{}, len(before)+len(after))
	for key := range before {
		keys[key] = struct{}{}
	}
	for key := range after {
		keys[key] = struct{}{}
	}
	if len(keys) == 0 {
		return nil
	}
	ordered := make([]string, 0, len(keys))
	for key := range keys {
		ordered = append(ordered, key)
	}
	sort.Strings(ordered)

	out := make([]EntityPropertyDiff, 0, len(ordered))
	for _, key := range ordered {
		beforeValue, beforeOK := before[key]
		afterValue, afterOK := after[key]
		if beforeOK && afterOK && reflect.DeepEqual(beforeValue, afterValue) {
			continue
		}
		change := EntityPropertyDiff{Key: key}
		if beforeOK {
			change.Before = cloneAny(beforeValue)
		}
		if afterOK {
			change.After = cloneAny(afterValue)
		}
		out = append(out, change)
	}
	return out
}
