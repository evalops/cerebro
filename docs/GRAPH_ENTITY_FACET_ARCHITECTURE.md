# Graph Entity Facet Architecture

This document describes the platform-level entity model that now sits between raw graph nodes and report/UI asset views.

The goal is to keep entity reads durable and typed while pushing richer presentation into report modules instead of bespoke asset endpoint trees.

## Core Model

Typed entity reads under `/api/v1/platform/entities*` now separate:

- canonical platform identity: `canonical_ref`
- source-native identity: `external_refs`
- alias context: `aliases`
- graph context: `relationships`, `links`
- knowledge context: `knowledge`
- asset deepening modules: `facets`
- normalized posture/support state: `posture`

This keeps the entity record small enough to stay reusable while making it rich enough for report composition.

## Canonical Identity

Every entity should expose one canonical ref with:

- `id`
- `kind`
- `namespace`
- `name`
- `provider`
- `account`
- `region`

Rules:

- `canonical_ref` is the platform identity, not the raw provider ID.
- `external_refs` retain provider-native identity such as ARNs, resource IDs, and source URLs.
- `aliases` capture explicit alternate identity records like `identity_alias -> alias_of`.

This mirrors the catalog/entity-ref pattern from Backstage while preserving graph-native IDs internally.

## Facet Contracts

Facets are schema-backed fragments materialized on entity detail.

Current built-in facets:

- `ownership`
- `exposure`
- `data_sensitivity`
- `bucket_public_access`
- `bucket_encryption`
- `bucket_logging`
- `bucket_versioning`

Facet rules:

- facets are not raw provider blobs
- facets must advertise stable IDs, schema names, and schema URLs
- facet fields should come from raw properties, graph relationships, and normalized claims
- new facets should be additive and backward-compatible

Facet assessment values should stay coarse and durable:

- `pass`
- `warn`
- `fail`
- `info`
- `unknown`

## Posture Model

Risk posture should not live only in `properties`.

Use:

- `properties` for raw observed configuration
- `observations` for low-level collected facts
- `evidence` for attached artifacts and scans
- `claims` for normalized posture statements

Entity detail exposes a `posture` block that summarizes active posture claims and their support/dispute state.

Current posture-oriented predicates include:

- `public_access`
- `internet_exposed`
- `encrypted`
- `default_encryption_enabled`
- `access_logging_enabled`
- `versioning_enabled`
- `backup_enabled`
- `contains_sensitive_data`
- `data_classification`

## Report Boundary

The richer asset view should be a report, not a new subtree of asset-specific APIs.

Current report surface:

- `GET /api/v1/platform/intelligence/entity-summary`
- `POST /api/v1/platform/intelligence/reports/entity-summary/runs`

The `entity-summary` report composes:

- `overview`
- `topology`
- `facets`
- `posture`
- `support`

This keeps asset pages aligned with the existing report registry, run lifecycle, snapshot lineage, and stream/event model.

## Promotion Rule

Promote a nested asset construct into its own node only when at least one is true:

- it has an independent lifecycle
- it needs provenance/evidence of its own
- it appears in explanations or remediation actions
- it can be linked from multiple parents

Likely next promotions:

- bucket policy statements
- security group rules
- service endpoints
- database tables/columns
- secret versions

## Next Tracks

1. Generate facet contract docs and compatibility checks from one canonical registry.
2. Deepen one asset family end-to-end with promoted subresources.
3. Add write-side posture normalization jobs so raw config becomes durable claims automatically.
4. Add entity-summary module overlays for docs/links, timeline, and remediation context.
