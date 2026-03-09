package graph

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// SchemaKindCount counts entities by kind.
type SchemaKindCount struct {
	Kind  string `json:"kind"`
	Count int    `json:"count"`
}

// SchemaIssueCount counts conformance issues by code/detail.
type SchemaIssueCount struct {
	Code   string `json:"code"`
	Detail string `json:"detail"`
	Count  int    `json:"count"`
}

// SchemaEntityCoverage summarizes coverage/conformance for one entity type.
type SchemaEntityCoverage struct {
	Total          int `json:"total"`
	RegisteredKind int `json:"registered_kind"`
	UnknownKind    int `json:"unknown_kind"`
	Conformant     int `json:"conformant"`
}

// SchemaHealthReport captures ontology coverage, conformance, and drift.
type SchemaHealthReport struct {
	GeneratedAt    time.Time            `json:"generated_at"`
	SchemaVersion  int64                `json:"schema_version"`
	SinceVersion   int64                `json:"since_version"`
	ValidationMode SchemaValidationMode `json:"validation_mode"`

	Nodes SchemaEntityCoverage `json:"nodes"`
	Edges SchemaEntityCoverage `json:"edges"`

	NodeKindCoveragePercent float64 `json:"node_kind_coverage_percent"`
	EdgeKindCoveragePercent float64 `json:"edge_kind_coverage_percent"`
	NodeConformancePercent  float64 `json:"node_conformance_percent"`
	EdgeConformancePercent  float64 `json:"edge_conformance_percent"`

	UnknownNodeKinds          []SchemaKindCount  `json:"unknown_node_kinds,omitempty"`
	UnknownEdgeKinds          []SchemaKindCount  `json:"unknown_edge_kinds,omitempty"`
	MissingRequiredProperties []SchemaIssueCount `json:"missing_required_properties,omitempty"`
	InvalidPropertyTypes      []SchemaIssueCount `json:"invalid_property_types,omitempty"`
	InvalidRelationships      []SchemaIssueCount `json:"invalid_relationships,omitempty"`

	Drift             SchemaDriftReport     `json:"drift"`
	RecentChanges     []SchemaChange        `json:"recent_changes,omitempty"`
	RuntimeValidation SchemaValidationStats `json:"runtime_validation"`
}

// AnalyzeSchemaHealth evaluates ontology quality against one graph snapshot.
func AnalyzeSchemaHealth(g *Graph, historyLimit int, sinceVersion int64) SchemaHealthReport {
	reg := GlobalSchemaRegistry()
	version := reg.Version()
	recent := reg.History(historyLimit)

	if sinceVersion <= 0 {
		sinceVersion = version
		if len(recent) > 0 {
			sinceVersion = recent[0].Version - 1
		}
		if sinceVersion < 1 {
			sinceVersion = 1
		}
	}

	report := SchemaHealthReport{
		GeneratedAt:    time.Now().UTC(),
		SchemaVersion:  version,
		SinceVersion:   sinceVersion,
		ValidationMode: SchemaValidationWarn,
		RecentChanges:  recent,
		Drift:          reg.DriftSince(sinceVersion),
	}
	if g == nil {
		return report
	}

	report.ValidationMode = g.SchemaValidationMode()
	report.RuntimeValidation = g.SchemaValidationStats()

	nodes := g.GetAllNodes()
	report.Nodes.Total = len(nodes)
	nodeByID := make(map[string]*Node, len(nodes))

	unknownNodeKinds := make(map[string]int)
	missingRequired := make(map[string]*SchemaIssueCount)
	invalidPropTypes := make(map[string]*SchemaIssueCount)

	for _, node := range nodes {
		if node == nil {
			continue
		}
		nodeByID[node.ID] = node
		if reg.IsNodeKindRegistered(node.Kind) {
			report.Nodes.RegisteredKind++
		} else {
			report.Nodes.UnknownKind++
			unknownNodeKinds[string(node.Kind)]++
		}

		issues := reg.ValidateNode(node)
		if len(issues) == 0 {
			report.Nodes.Conformant++
			continue
		}
		for _, issue := range issues {
			switch issue.Code {
			case SchemaIssueMissingRequiredProperty:
				detail := strings.TrimSpace(fmt.Sprintf("%s.%s", issue.Kind, issue.Property))
				addSchemaIssueCount(missingRequired, string(issue.Code), detail)
			case SchemaIssueInvalidPropertyType:
				detail := strings.TrimSpace(fmt.Sprintf("%s.%s", issue.Kind, issue.Property))
				addSchemaIssueCount(invalidPropTypes, string(issue.Code), detail)
			}
		}
	}

	unknownEdgeKinds := make(map[string]int)
	invalidRelationships := make(map[string]*SchemaIssueCount)

	for _, edges := range g.GetAllEdges() {
		for _, edge := range edges {
			if edge == nil {
				continue
			}
			report.Edges.Total++
			if reg.IsEdgeKindRegistered(edge.Kind) {
				report.Edges.RegisteredKind++
			} else {
				report.Edges.UnknownKind++
				unknownEdgeKinds[string(edge.Kind)]++
			}

			issues := reg.ValidateEdge(edge, nodeByID[edge.Source], nodeByID[edge.Target])
			if len(issues) == 0 {
				report.Edges.Conformant++
				continue
			}
			for _, issue := range issues {
				switch issue.Code {
				case SchemaIssueRelationshipNotAllowed,
					SchemaIssueMissingSourceNode,
					SchemaIssueMissingTargetNode,
					SchemaIssueUnknownSourceKind,
					SchemaIssueUnknownTargetKind:
					addSchemaIssueCount(invalidRelationships, string(issue.Code), issue.Message)
				}
			}
		}
	}

	report.NodeKindCoveragePercent = percent(report.Nodes.RegisteredKind, report.Nodes.Total)
	report.EdgeKindCoveragePercent = percent(report.Edges.RegisteredKind, report.Edges.Total)
	report.NodeConformancePercent = percent(report.Nodes.Conformant, report.Nodes.Total)
	report.EdgeConformancePercent = percent(report.Edges.Conformant, report.Edges.Total)
	report.UnknownNodeKinds = sortedSchemaKindCounts(unknownNodeKinds)
	report.UnknownEdgeKinds = sortedSchemaKindCounts(unknownEdgeKinds)
	report.MissingRequiredProperties = sortedSchemaIssueCounts(missingRequired)
	report.InvalidPropertyTypes = sortedSchemaIssueCounts(invalidPropTypes)
	report.InvalidRelationships = sortedSchemaIssueCounts(invalidRelationships)
	return report
}

func addSchemaIssueCount(target map[string]*SchemaIssueCount, code, detail string) {
	code = strings.TrimSpace(code)
	detail = strings.TrimSpace(detail)
	key := code + "|" + detail
	if issue, ok := target[key]; ok {
		issue.Count++
		return
	}
	target[key] = &SchemaIssueCount{
		Code:   code,
		Detail: detail,
		Count:  1,
	}
}

func sortedSchemaKindCounts(values map[string]int) []SchemaKindCount {
	if len(values) == 0 {
		return nil
	}
	out := make([]SchemaKindCount, 0, len(values))
	for kind, count := range values {
		kind = strings.TrimSpace(kind)
		if kind == "" {
			kind = "<empty>"
		}
		out = append(out, SchemaKindCount{Kind: kind, Count: count})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count == out[j].Count {
			return out[i].Kind < out[j].Kind
		}
		return out[i].Count > out[j].Count
	})
	return out
}

func sortedSchemaIssueCounts(values map[string]*SchemaIssueCount) []SchemaIssueCount {
	if len(values) == 0 {
		return nil
	}
	out := make([]SchemaIssueCount, 0, len(values))
	for _, issue := range values {
		if issue == nil {
			continue
		}
		out = append(out, *issue)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count == out[j].Count {
			if out[i].Code == out[j].Code {
				return out[i].Detail < out[j].Detail
			}
			return out[i].Code < out[j].Code
		}
		return out[i].Count > out[j].Count
	})
	return out
}

func percent(numerator, denominator int) float64 {
	if denominator <= 0 {
		return 0
	}
	return (float64(numerator) / float64(denominator)) * 100
}
