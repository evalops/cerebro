package app

import (
	"reflect"
	"strings"

	"github.com/evalops/cerebro/internal/dspm"
	"github.com/evalops/cerebro/internal/graph"
)

func (a *App) enrichSecurityGraphWithDSPMResult(target *dspm.ScanTarget, result *dspm.ScanResult) {
	if a == nil || a.DSPM == nil || target == nil {
		return
	}

	nodeIDs := dspmGraphNodeIDs(target)
	if len(nodeIDs) == 0 {
		return
	}

	props := a.DSPM.EnrichGraphNode(result)
	if len(props) == 0 {
		return
	}

	a.graphUpdateMu.Lock()
	defer a.graphUpdateMu.Unlock()

	var builderSecurityGraph *graph.Graph
	if a.SecurityGraphBuilder != nil {
		builderSecurityGraph = a.SecurityGraphBuilder.Graph()
	}

	seen := make(map[*graph.Graph]struct{}, 2)
	for _, g := range []*graph.Graph{a.CurrentSecurityGraph(), builderSecurityGraph} {
		if g == nil {
			continue
		}
		if _, ok := seen[g]; ok {
			continue
		}
		seen[g] = struct{}{}
		applyDSPMPropertiesToGraph(g, nodeIDs, props)
	}
}

func applyDSPMPropertiesToGraph(g *graph.Graph, nodeIDs []string, props map[string]any) bool {
	if g == nil || len(nodeIDs) == 0 || len(props) == 0 {
		return false
	}

	for _, nodeID := range nodeIDs {
		nodeID = strings.TrimSpace(nodeID)
		if nodeID == "" {
			continue
		}

		node, ok := g.GetNode(nodeID)
		if !ok || node == nil {
			continue
		}

		for key, value := range props {
			existing, exists := node.Properties[key]
			if exists && reflect.DeepEqual(existing, value) {
				continue
			}
			g.SetNodeProperty(nodeID, key, value)
		}
		return true
	}

	return false
}

func dspmGraphNodeIDs(target *dspm.ScanTarget) []string {
	if target == nil {
		return nil
	}

	ids := make([]string, 0, 8)
	if target.Properties != nil {
		appendUniqueGraphNodeIDs(&ids,
			firstNonEmptyString(target.Properties, "arn", "resource_arn"),
			firstNonEmptyString(target.Properties, "resource_id", "id"),
			firstNonEmptyString(target.Properties, "bucket_name", "name"),
		)
	}
	appendUniqueGraphNodeIDs(&ids, target.ARN, target.ID, target.Name)
	if target.Properties != nil {
		appendUniqueGraphNodeIDs(&ids, firstNonEmptyString(target.Properties, "_cq_id"))
	}
	return ids
}

func appendUniqueGraphNodeIDs(ids *[]string, values ...string) {
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			continue
		}
		exists := false
		for _, existing := range *ids {
			if existing == trimmed {
				exists = true
				break
			}
		}
		if !exists {
			*ids = append(*ids, trimmed)
		}
	}
}
