package graph

import (
	"testing"
	"time"
)

func TestCompareEntityFacetContractCatalogsMarksVersionBumpedBreaksIncompatible(t *testing.T) {
	baseline := EntityFacetContractCatalog{
		APIVersion: defaultEntityFacetContractCatalogAPIVersion,
		Kind:       defaultEntityFacetContractCatalogKind,
		Facets: []EntityFacetDefinition{
			{
				ID:         "ownership",
				Version:    "1.0.0",
				Title:      "Ownership",
				SchemaName: "PlatformEntityOwnershipFacet",
				SchemaURL:  "urn:cerebro:entity-facet:ownership:v1",
				Fields: []EntityFacetFieldDefinition{
					{Key: "owner_ids", ValueType: "array[string]"},
				},
			},
		},
	}
	current := EntityFacetContractCatalog{
		APIVersion: defaultEntityFacetContractCatalogAPIVersion,
		Kind:       defaultEntityFacetContractCatalogKind,
		Facets: []EntityFacetDefinition{
			{
				ID:         "ownership",
				Version:    "2.0.0",
				Title:      "Ownership",
				SchemaName: "PlatformEntityOwnershipFacet",
				SchemaURL:  "urn:cerebro:entity-facet:ownership:v2",
				Fields: []EntityFacetFieldDefinition{
					{Key: "owner_ids", ValueType: "array[string]"},
					{Key: "manager_ids", ValueType: "array[string]"},
				},
			},
		},
	}

	report := CompareEntityFacetContractCatalogs(baseline, current, time.Date(2026, 3, 10, 12, 0, 0, 0, time.UTC))
	if report.Compatible {
		t.Fatalf("expected breaking change to be incompatible, got %#v", report)
	}
	if len(report.BreakingChanges) != 1 {
		t.Fatalf("expected exactly one breaking change, got %#v", report.BreakingChanges)
	}
	if len(report.VersioningViolations) != 0 {
		t.Fatalf("expected no versioning violations for version bump, got %#v", report.VersioningViolations)
	}
}

func TestCompareEntityFacetContractCatalogsTreatsRemovalAsBreakingNotVersioning(t *testing.T) {
	baseline := EntityFacetContractCatalog{
		APIVersion: defaultEntityFacetContractCatalogAPIVersion,
		Kind:       defaultEntityFacetContractCatalogKind,
		Facets: []EntityFacetDefinition{
			{
				ID:         "ownership",
				Version:    "1.0.0",
				Title:      "Ownership",
				SchemaName: "PlatformEntityOwnershipFacet",
				SchemaURL:  "urn:cerebro:entity-facet:ownership:v1",
			},
		},
	}
	current := EntityFacetContractCatalog{
		APIVersion: defaultEntityFacetContractCatalogAPIVersion,
		Kind:       defaultEntityFacetContractCatalogKind,
	}

	report := CompareEntityFacetContractCatalogs(baseline, current, time.Date(2026, 3, 10, 12, 30, 0, 0, time.UTC))
	if len(report.BreakingChanges) != 1 {
		t.Fatalf("expected a removal to register as one breaking change, got %#v", report.BreakingChanges)
	}
	if len(report.VersioningViolations) != 0 {
		t.Fatalf("expected removals to stay out of versioning violations, got %#v", report.VersioningViolations)
	}
}
