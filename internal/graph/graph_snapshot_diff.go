package graph

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"
)

// GraphSnapshotReference is the lightweight snapshot handle embedded in ancestry and diff resources.
type GraphSnapshotReference struct {
	ID         string     `json:"id"`
	BuiltAt    *time.Time `json:"built_at,omitempty"`
	CapturedAt *time.Time `json:"captured_at,omitempty"`
	Current    bool       `json:"current,omitempty"`
	Diffable   bool       `json:"diffable,omitempty"`
}

// GraphSnapshotAncestry captures the ordered neighborhood of one graph snapshot.
type GraphSnapshotAncestry struct {
	SnapshotID  string                   `json:"snapshot_id"`
	Position    int                      `json:"position"`
	Count       int                      `json:"count"`
	Previous    *GraphSnapshotReference  `json:"previous,omitempty"`
	Next        *GraphSnapshotReference  `json:"next,omitempty"`
	Ancestors   []GraphSnapshotReference `json:"ancestors,omitempty"`
	Descendants []GraphSnapshotReference `json:"descendants,omitempty"`
}

// GraphSnapshotDiffSummary captures the high-level shape of one structural graph diff.
type GraphSnapshotDiffSummary struct {
	NodesAdded    int `json:"nodes_added"`
	NodesRemoved  int `json:"nodes_removed"`
	NodesModified int `json:"nodes_modified"`
	EdgesAdded    int `json:"edges_added"`
	EdgesRemoved  int `json:"edges_removed"`
}

// GraphSnapshotDiffRecord is the typed diff resource between two graph snapshots.
type GraphSnapshotDiffRecord struct {
	ID          string                   `json:"id"`
	GeneratedAt time.Time                `json:"generated_at"`
	From        GraphSnapshotReference   `json:"from"`
	To          GraphSnapshotReference   `json:"to"`
	Summary     GraphSnapshotDiffSummary `json:"summary"`
	Diff        GraphDiff                `json:"diff"`
}

// GraphSnapshotAncestryFromCollection derives ordered ancestry metadata from a snapshot collection.
func GraphSnapshotAncestryFromCollection(collection GraphSnapshotCollection, snapshotID string) (*GraphSnapshotAncestry, bool) {
	snapshotID = strings.TrimSpace(snapshotID)
	if snapshotID == "" {
		return nil, false
	}
	ordered := append([]GraphSnapshotRecord(nil), collection.Snapshots...)
	sort.Slice(ordered, func(i, j int) bool {
		left := graphSnapshotSortTime(ordered[i])
		right := graphSnapshotSortTime(ordered[j])
		if !left.Equal(right) {
			return left.Before(right)
		}
		return ordered[i].ID < ordered[j].ID
	})
	index := -1
	for i := range ordered {
		if strings.TrimSpace(ordered[i].ID) == snapshotID {
			index = i
			break
		}
	}
	if index == -1 {
		return nil, false
	}
	ancestry := &GraphSnapshotAncestry{
		SnapshotID: snapshotID,
		Position:   index + 1,
		Count:      len(ordered),
	}
	if index > 0 {
		prev := graphSnapshotReference(ordered[index-1])
		ancestry.Previous = &prev
		ancestry.Ancestors = make([]GraphSnapshotReference, 0, index)
		for i := index - 1; i >= 0; i-- {
			ancestry.Ancestors = append(ancestry.Ancestors, graphSnapshotReference(ordered[i]))
		}
	}
	if index+1 < len(ordered) {
		next := graphSnapshotReference(ordered[index+1])
		ancestry.Next = &next
		ancestry.Descendants = make([]GraphSnapshotReference, 0, len(ordered)-index-1)
		for i := index + 1; i < len(ordered); i++ {
			ancestry.Descendants = append(ancestry.Descendants, graphSnapshotReference(ordered[i]))
		}
	}
	return ancestry, true
}

// BuildGraphSnapshotDiffRecord constructs a typed diff resource between two snapshots.
func BuildGraphSnapshotDiffRecord(from, to GraphSnapshotRecord, diff *GraphDiff, now time.Time) *GraphSnapshotDiffRecord {
	if diff == nil {
		return nil
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	record := &GraphSnapshotDiffRecord{
		ID:          graphSnapshotDiffID(from.ID, to.ID),
		GeneratedAt: now.UTC(),
		From:        graphSnapshotReference(from),
		To:          graphSnapshotReference(to),
		Summary: GraphSnapshotDiffSummary{
			NodesAdded:    len(diff.NodesAdded),
			NodesRemoved:  len(diff.NodesRemoved),
			NodesModified: len(diff.NodesModified),
			EdgesAdded:    len(diff.EdgesAdded),
			EdgesRemoved:  len(diff.EdgesRemoved),
		},
		Diff: *diff,
	}
	return record
}

func graphSnapshotReference(record GraphSnapshotRecord) GraphSnapshotReference {
	return GraphSnapshotReference{
		ID:         strings.TrimSpace(record.ID),
		BuiltAt:    cloneTimePtr(record.BuiltAt),
		CapturedAt: cloneTimePtr(record.CapturedAt),
		Current:    record.Current,
		Diffable:   record.Diffable,
	}
}

func graphSnapshotDiffID(fromSnapshotID, toSnapshotID string) string {
	payload := fmt.Sprintf("%s|%s", strings.TrimSpace(fromSnapshotID), strings.TrimSpace(toSnapshotID))
	sum := sha256.Sum256([]byte(payload))
	return "graph_snapshot_diff:" + hex.EncodeToString(sum[:12])
}
