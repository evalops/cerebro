package graph

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
)

const (
	defaultEntityFacetContractCatalogAPIVersion = "cerebro.entity-facets/v1alpha1"
	defaultEntityFacetContractCatalogKind       = "EntityFacetContractCatalog"
)

// EntityFacetContractCatalog captures the machine-readable contract surface for entity facets.
type EntityFacetContractCatalog struct {
	APIVersion  string                  `json:"apiVersion"`
	Kind        string                  `json:"kind"`
	GeneratedAt time.Time               `json:"generated_at,omitempty"`
	Facets      []EntityFacetDefinition `json:"facets,omitempty"`
}

// EntityFacetCompatibilityIssue captures one compatibility-affecting change.
type EntityFacetCompatibilityIssue struct {
	FacetID         string `json:"facet_id,omitempty"`
	ChangeType      string `json:"change_type"`
	Detail          string `json:"detail"`
	PreviousVersion string `json:"previous_version,omitempty"`
	CurrentVersion  string `json:"current_version,omitempty"`
}

// EntityFacetDiffSummary captures field-level diff paths for one changed facet contract.
type EntityFacetDiffSummary struct {
	FacetID         string   `json:"facet_id,omitempty"`
	PreviousVersion string   `json:"previous_version,omitempty"`
	CurrentVersion  string   `json:"current_version,omitempty"`
	AddedPaths      []string `json:"added_paths,omitempty"`
	RemovedPaths    []string `json:"removed_paths,omitempty"`
	ChangedPaths    []string `json:"changed_paths,omitempty"`
}

// EntityFacetCompatibilityReport summarizes compatibility drift between baseline and current facet catalogs.
type EntityFacetCompatibilityReport struct {
	GeneratedAt          time.Time                       `json:"generated_at"`
	BaselineFacets       int                             `json:"baseline_facets"`
	CurrentFacets        int                             `json:"current_facets"`
	AddedFacets          []string                        `json:"added_facets,omitempty"`
	RemovedFacets        []string                        `json:"removed_facets,omitempty"`
	BreakingChanges      []EntityFacetCompatibilityIssue `json:"breaking_changes,omitempty"`
	VersioningViolations []EntityFacetCompatibilityIssue `json:"versioning_violations,omitempty"`
	DiffSummaries        []EntityFacetDiffSummary        `json:"diff_summaries,omitempty"`
	Compatible           bool                            `json:"compatible"`
}

func BuildEntityFacetContractCatalog(now time.Time) EntityFacetContractCatalog {
	// Zero time is preserved intentionally so generated artifacts can omit
	// generated_at and remain deterministic across runs. API callers that need a
	// timestamp should pass an explicit time.
	if !now.IsZero() {
		now = now.UTC()
	}
	return EntityFacetContractCatalog{
		APIVersion:  defaultEntityFacetContractCatalogAPIVersion,
		Kind:        defaultEntityFacetContractCatalogKind,
		GeneratedAt: now,
		Facets:      ListEntityFacetDefinitions(),
	}
}

func CompareEntityFacetContractCatalogs(baseline, current EntityFacetContractCatalog, now time.Time) EntityFacetCompatibilityReport {
	if now.IsZero() {
		now = time.Now().UTC()
	} else {
		now = now.UTC()
	}
	report := EntityFacetCompatibilityReport{
		GeneratedAt:    now,
		BaselineFacets: len(baseline.Facets),
		CurrentFacets:  len(current.Facets),
		Compatible:     true,
	}
	baselineByID := make(map[string]EntityFacetDefinition, len(baseline.Facets))
	for _, facet := range baseline.Facets {
		baselineByID[strings.TrimSpace(facet.ID)] = facet
	}
	currentByID := make(map[string]EntityFacetDefinition, len(current.Facets))
	for _, facet := range current.Facets {
		currentByID[strings.TrimSpace(facet.ID)] = facet
	}
	ids := make(map[string]struct{}, len(baselineByID)+len(currentByID))
	for id := range baselineByID {
		ids[id] = struct{}{}
	}
	for id := range currentByID {
		ids[id] = struct{}{}
	}
	ordered := make([]string, 0, len(ids))
	for id := range ids {
		ordered = append(ordered, id)
	}
	sort.Strings(ordered)
	for _, id := range ordered {
		before, hadBefore := baselineByID[id]
		after, hasAfter := currentByID[id]
		switch {
		case hadBefore && !hasAfter:
			issue := EntityFacetCompatibilityIssue{
				FacetID:         id,
				ChangeType:      "removed",
				Detail:          fmt.Sprintf("facet %q was removed", id),
				PreviousVersion: strings.TrimSpace(before.Version),
			}
			report.RemovedFacets = append(report.RemovedFacets, id)
			report.BreakingChanges = append(report.BreakingChanges, issue)
			report.VersioningViolations = append(report.VersioningViolations, issue)
		case !hadBefore && hasAfter:
			report.AddedFacets = append(report.AddedFacets, id)
		case hadBefore && hasAfter:
			if entityFacetFingerprint(before) == entityFacetFingerprint(after) {
				continue
			}
			issue := EntityFacetCompatibilityIssue{
				FacetID:         id,
				ChangeType:      "changed",
				Detail:          fmt.Sprintf("facet %q contract changed", id),
				PreviousVersion: strings.TrimSpace(before.Version),
				CurrentVersion:  strings.TrimSpace(after.Version),
			}
			report.BreakingChanges = append(report.BreakingChanges, issue)
			if issue.PreviousVersion == issue.CurrentVersion {
				report.VersioningViolations = append(report.VersioningViolations, issue)
			}
			report.DiffSummaries = append(report.DiffSummaries, buildEntityFacetDiffSummary(issue, before, after))
		}
	}
	sort.Strings(report.AddedFacets)
	sort.Strings(report.RemovedFacets)
	report.Compatible = len(report.BreakingChanges) == 0 && len(report.VersioningViolations) == 0
	return report
}

func entityFacetFingerprint(value EntityFacetDefinition) string {
	normalized := value
	normalized.Version = ""
	payload, _ := json.Marshal(normalized)
	return string(payload)
}

func buildEntityFacetDiffSummary(issue EntityFacetCompatibilityIssue, before, after EntityFacetDefinition) EntityFacetDiffSummary {
	added, removed, changed := reportContractDiffPaths(before, after)
	return EntityFacetDiffSummary{
		FacetID:         issue.FacetID,
		PreviousVersion: issue.PreviousVersion,
		CurrentVersion:  issue.CurrentVersion,
		AddedPaths:      added,
		RemovedPaths:    removed,
		ChangedPaths:    changed,
	}
}
