# Function Scan Architecture

Cerebro's serverless function scanning pipeline should be durable, API-driven, and analyzable as an execution resource. It should not depend on process-local state or one-off cloud-specific code paths.

## Goals

- Model function scan runs and lifecycle events as typed persisted records.
- Acquire deployment packages through control-plane APIs instead of VM snapshots or ad hoc local exports.
- Reconstruct the effective function filesystem safely enough for shared analyzer reuse.
- Reuse the same execution-store durability boundary as workload and image scans.
- Keep provider-specific package acquisition behind narrow interfaces so deeper analyzers and graph integration can evolve independently.

## Runtime Model

The runtime persists state in SQLite via `internal/functionscan.SQLiteRunStore`.

Persisted records:

- `RunRecord`: one execution resource for a submitted function package scan
- `RunEvent`: append-only lifecycle and debugging timeline
- `FilesystemArtifact`: materialized package metadata, retention, and cleanup timestamps
- `AppliedArtifact`: ordered package/layer application metadata

By default, function scans now use the same `EXECUTION_STORE_FILE` fallback as workload and image scans. The tables are still runtime-specific, but the durability boundary is intentionally shared so scans stop creating new in-memory silos.

## Execution Pipeline

Current run stages:

1. `queued`
2. `describe`
3. `materialize`
4. `analyze`
5. `cleanup`
6. `completed` or `failed`

The pipeline is intentionally narrow:

- provider metadata/package acquisition belongs in `internal/functionscan`
- vulnerability/secret/runtime analysis belongs in the shared filesystem analyzer seam
- graph contextualization belongs in later issues (`#181`, `#182`)

## Provider Substrate

Current provider support:

- `AWSProvider`
- `GCPProvider`
- `AzureProvider`

Current acquisition path by provider:

- AWS Lambda:
  - `GetFunction` for runtime/config/env/code metadata
  - presigned function ZIP download
  - `GetLayerVersionByArn` for attached layer ZIP downloads
  - effective filesystem reconstructed as layers first, function ZIP last
- GCP Cloud Functions:
  - `GetFunction` for runtime/build/service metadata
  - Cloud Storage source archive download when a storage source is present
  - container-backed v2 functions remain visible through metadata even when no source archive is available
- Azure Functions:
  - `WebAppsClient.Get` for site metadata
  - `ListApplicationSettings` for runtime/env/package location
  - `WEBSITE_RUN_FROM_PACKAGE` / `SCM_RUN_FROM_PACKAGE` URL download when exposed

## Materialization Rules

The local materializer:

- writes archives beneath a bounded rootfs base path
- rejects symlink zip entries
- rejects traversal or intermediary symlink breakout
- applies artifacts in declared order
- removes temporary archive files after application

This is the current local durability boundary, not the final distributed executor design.

## Analyzer Contract

The runtime depends on a small analyzer seam:

- `Analyzer`
- current concrete: `FilesystemAnalyzer` backed by `scanner.TrivyFilesystemScanner`
- fallback: `NoopAnalyzer`

Current analysis coverage:

- filesystem vulnerability scan through Trivy
- secrets in function environment variables
- secrets in materialized source/package files
- curated runtime deprecation detection

This is intentionally thinner than the deeper package/SBOM/vulnerability knowledge work in issue `#180` / `#181`.

## Lifecycle Events

The runtime emits webhook-compatible lifecycle events:

- `security.function_scan.started`
- `security.function_scan.completed`
- `security.function_scan.failed`

These events are the current bridge into later graph/attack-path contextualization from issue `#182`.

## OSS Patterns Reused

The implementation is intentionally borrowing shape from a few mature projects:

- `aquasecurity/trivy`: filesystem-oriented vulnerability scanning as the common analyzer substrate
- `anchore/syft`: treat a reconstructed filesystem as the stable package/SBOM analysis boundary
- `semgrep/semgrep`: source-tree oriented static inspection as a later extension point for code/package analysis
- `google/osv-scanner`: package/ecosystem vulnerability matching model that should feed the later knowledge pipeline

## Known Limits

- SQLite is durable, but still single-node.
- GCP v2 container-backed functions are described, but full container-image fallback should converge with the image-scan runtime instead of duplicating registry logic here.
- Runtime EOL detection is currently curated/manual rather than sourced from a continuously-updated advisory feed.
- The analyzer still relies on Trivy FS plus lightweight secret heuristics; richer package/SBOM/config analysis belongs in issue `#180`.

## Next Steps

1. Converge serverless/container/VM analyzers on the richer filesystem analyzer from issue `#180`.
2. Feed package and vulnerability outputs into the vulnerability knowledge pipeline from issue `#181`.
3. Link function scan runs, packages, vulnerabilities, and runtime exposure into the temporal security graph from issue `#182`.
4. Extract workload/image/function runtimes onto a real shared execution-store package once the execution surface stabilizes.
