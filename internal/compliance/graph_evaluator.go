package compliance

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/evalops/cerebro/internal/graph"
)

const maxControlEvidence = 25

// EvaluationOptions tunes graph-backed compliance evaluation.
type EvaluationOptions struct {
	ValidAt              time.Time
	RecordedAt           time.Time
	GeneratedAt          time.Time
	OpenFindingsByPolicy map[string]int
}

// EvaluateFramework derives compliance control status from the current graph where possible,
// and falls back to findings counts for controls the graph cannot yet evaluate directly.
func EvaluateFramework(g *graph.Graph, framework *Framework, opts EvaluationOptions) ComplianceReport {
	if framework == nil {
		return ComplianceReport{}
	}
	now := opts.GeneratedAt.UTC()
	if now.IsZero() {
		now = time.Now().UTC()
	}
	validAt := opts.ValidAt.UTC()
	if validAt.IsZero() {
		validAt = now
	}
	recordedAt := opts.RecordedAt.UTC()
	if recordedAt.IsZero() {
		recordedAt = now
	}

	evaluator := graphComplianceEvaluator{
		graph:                g,
		validAt:              validAt,
		recordedAt:           recordedAt,
		generatedAt:          now,
		openFindingsByPolicy: cloneFindingCounts(opts.OpenFindingsByPolicy),
		entityCache:          make(map[string][]graph.EntityRecord),
	}

	report := ComplianceReport{
		FrameworkID:   framework.ID,
		FrameworkName: framework.Name,
		GeneratedAt:   now.Format(time.RFC3339),
		Summary: ComplianceSummary{
			TotalControls: len(framework.Controls),
		},
		Controls: make([]ControlStatus, 0, len(framework.Controls)),
	}
	failingControlIDs := make(map[string]bool)

	for _, ctrl := range framework.Controls {
		status := evaluator.evaluateControl(ctrl)
		report.Controls = append(report.Controls, status)
		switch status.Status {
		case ControlStatePassing:
			report.Summary.PassingControls++
		case ControlStateFailing:
			report.Summary.FailingControls++
			failingControlIDs[status.ControlID] = true
		case ControlStatePartial, ControlStateUnknown:
			report.Summary.PartialControls++
			failingControlIDs[status.ControlID] = true
		case ControlStateNotApplicable:
			report.Summary.NotApplicableControls++
		}
		switch status.EvaluationSource {
		case ControlEvaluationSourceGraph, ControlEvaluationSourceHybrid:
			report.Summary.GraphEvaluatedControls++
		}
		switch status.EvaluationSource {
		case ControlEvaluationSourceFindingsFallback, ControlEvaluationSourceHybrid:
			report.Summary.FallbackControls++
		}
	}

	assessed := report.Summary.TotalControls - report.Summary.NotApplicableControls
	if assessed <= 0 {
		report.Summary.ComplianceScore = 100
	} else {
		report.Summary.ComplianceScore = float64(report.Summary.PassingControls) / float64(assessed) * 100
	}
	report.Summary.WeightedScore, _, _ = CalculateWeightedScore(framework.Controls, failingControlIDs)
	return report
}

type graphComplianceEvaluator struct {
	graph                *graph.Graph
	validAt              time.Time
	recordedAt           time.Time
	generatedAt          time.Time
	openFindingsByPolicy map[string]int
	entityCache          map[string][]graph.EntityRecord
}

type policyEvaluation struct {
	PolicyID      string
	Supported     bool
	Source        string
	Status        string
	Applicable    int
	Passing       int
	Failing       int
	Evidence      []ControlEvidence
	FailEntityIDs map[string]struct{}
	PassEntityIDs map[string]struct{}
}

func (e *graphComplianceEvaluator) evaluateControl(ctrl Control) ControlStatus {
	policyResults := make([]policyEvaluation, 0, len(ctrl.PolicyIDs))
	hasGraph := false
	hasFallback := false

	for _, policyID := range ctrl.PolicyIDs {
		result := e.evaluatePolicy(policyID)
		if !result.Supported {
			result = e.fallbackPolicy(policyID)
		}
		if result.Source == ControlEvaluationSourceGraph {
			hasGraph = true
		}
		if result.Source == ControlEvaluationSourceFindingsFallback {
			hasFallback = true
		}
		policyResults = append(policyResults, result)
	}

	status := ControlStatus{
		ControlID:     ctrl.ID,
		Title:         ctrl.Title,
		Description:   ctrl.Description,
		Severity:      ctrl.Severity,
		Status:        ControlStateUnknown,
		LastEvaluated: e.generatedAt.Format(time.RFC3339),
		PolicyIDs:     append([]string(nil), ctrl.PolicyIDs...),
	}

	failIDs := make(map[string]struct{})
	passIDs := make(map[string]struct{})
	notApplicablePolicies := 0
	evidence := make([]ControlEvidence, 0)
	anyFail := false
	anyPass := false
	anyPartial := false

	for _, result := range policyResults {
		for id := range result.FailEntityIDs {
			failIDs[id] = struct{}{}
		}
		for id := range result.PassEntityIDs {
			passIDs[id] = struct{}{}
		}
		evidence = append(evidence, result.Evidence...)
		switch result.Status {
		case ControlStateFailing:
			anyFail = true
		case ControlStatePassing:
			anyPass = true
		case ControlStatePartial, ControlStateUnknown:
			anyPartial = true
		case ControlStateNotApplicable:
			notApplicablePolicies++
		}
	}

	if anyFail {
		status.Status = ControlStateFailing
	} else if anyPartial {
		status.Status = ControlStatePartial
	} else if anyPass {
		status.Status = ControlStatePassing
	} else if len(policyResults) > 0 && notApplicablePolicies == len(policyResults) {
		status.Status = ControlStateNotApplicable
	}

	status.FailCount = len(failIDs)
	status.PassCount = len(passIDs)
	status.TotalAssets = len(unionStringSets(failIDs, passIDs))
	if hasGraph && hasFallback {
		status.EvaluationSource = ControlEvaluationSourceHybrid
	} else if hasGraph {
		status.EvaluationSource = ControlEvaluationSourceGraph
	} else {
		status.EvaluationSource = ControlEvaluationSourceFindingsFallback
	}
	if len(evidence) > maxControlEvidence {
		evidence = evidence[:maxControlEvidence]
	}
	status.Evidence = evidence
	return status
}

func (e *graphComplianceEvaluator) evaluatePolicy(policyID string) policyEvaluation {
	switch strings.TrimSpace(policyID) {
	case "aws-s3-bucket-encryption-enabled":
		return e.evaluateFacetBoolPolicy(policyID, "aws", []graph.NodeKind{graph.NodeKindBucket}, "bucket_encryption", "encrypted", true, "Bucket encryption is enabled", "Bucket encryption is disabled or incomplete")
	case "aws-s3-bucket-no-public-access":
		return e.evaluateFacetBoolPolicy(policyID, "aws", []graph.NodeKind{graph.NodeKindBucket}, "bucket_public_access", "public_access", false, "Bucket is not publicly accessible", "Bucket is publicly accessible")
	case "aws-s3-bucket-policy-public":
		return e.evaluateBucketPublicPolicy(policyID, "aws")
	case "aws-s3-bucket-logging-enabled":
		return e.evaluateFacetBoolPolicy(policyID, "aws", []graph.NodeKind{graph.NodeKindBucket}, "bucket_logging", "logging_enabled", true, "Bucket access logging is enabled", "Bucket access logging is disabled")
	case "aws-s3-bucket-versioning-enabled":
		return e.evaluateBucketVersioning(policyID, "aws")
	case "aws-rds-encryption-enabled":
		return e.evaluatePropertyBoolPolicy(policyID, "aws", []graph.NodeKind{graph.NodeKindDatabase}, []string{"encrypted", "storage_encrypted", "kms_encrypted"}, true, "", "Database encryption is enabled", "Database encryption is disabled")
	case "aws-rds-no-public-access":
		return e.evaluatePropertyBoolPolicy(policyID, "aws", []graph.NodeKind{graph.NodeKindDatabase}, []string{"public", "public_access", "publicly_accessible"}, false, "", "Database is not publicly accessible", "Database is publicly accessible")
	case "dspm-restricted-data-unencrypted":
		return e.evaluateSensitiveDataEncryption(policyID)
	case "dspm-confidential-data-public":
		return e.evaluateSensitiveDataExposure(policyID)
	case "gcp-storage-bucket-no-public":
		return e.evaluateFacetBoolPolicy(policyID, "gcp", []graph.NodeKind{graph.NodeKindBucket}, "bucket_public_access", "public_access", false, "Bucket is not publicly accessible", "Bucket is publicly accessible")
	case "gcp-storage-no-public-allusers":
		return e.evaluateBucketPublicPolicy(policyID, "gcp")
	case "gcp-iam-sa-no-admin-privileges", "gcp-sa-admin-privileges":
		return e.evaluateServiceAccountAdminPrivileges(policyID)
	case "gcp-service-account-key-rotation":
		return e.evaluateServiceAccountKeyRotation(policyID)
	case "gcp-iam-minimize-user-managed-keys":
		return e.evaluateServiceAccountMinimizeKeys(policyID)
	default:
		return policyEvaluation{PolicyID: policyID}
	}
}

func (e *graphComplianceEvaluator) fallbackPolicy(policyID string) policyEvaluation {
	count := e.openFindingsByPolicy[strings.TrimSpace(policyID)]
	result := policyEvaluation{
		PolicyID:      policyID,
		Supported:     true,
		Source:        ControlEvaluationSourceFindingsFallback,
		FailEntityIDs: make(map[string]struct{}),
		PassEntityIDs: make(map[string]struct{}),
	}
	if count > 0 {
		result.Status = ControlStateFailing
		result.Failing = count
		result.Evidence = []ControlEvidence{{
			PolicyID: policyID,
			Status:   ControlStateFailing,
			Reason:   fmt.Sprintf("%d open findings mapped to policy %s", count, policyID),
		}}
		return result
	}
	result.Status = ControlStatePassing
	result.Evidence = []ControlEvidence{{
		PolicyID: policyID,
		Status:   ControlStatePassing,
		Reason:   fmt.Sprintf("No open findings mapped to policy %s", policyID),
	}}
	return result
}

func (e *graphComplianceEvaluator) evaluateFacetBoolPolicy(policyID, provider string, kinds []graph.NodeKind, facetID, field string, expected bool, passReason, failReason string) policyEvaluation {
	records := e.entityRecords(provider, kinds...)
	result := policyEvaluation{
		PolicyID:      policyID,
		Supported:     true,
		Source:        ControlEvaluationSourceGraph,
		FailEntityIDs: make(map[string]struct{}),
		PassEntityIDs: make(map[string]struct{}),
	}
	if len(records) == 0 {
		result.Status = ControlStateNotApplicable
		return result
	}
	unknown := 0
	for _, record := range records {
		facet, ok := entityFacet(record, facetID)
		if !ok {
			unknown++
			continue
		}
		value, ok := boolField(facet.Fields, field)
		if !ok {
			unknown++
			continue
		}
		result.Applicable++
		if value == expected {
			result.Passing++
			result.PassEntityIDs[record.ID] = struct{}{}
			result.Evidence = append(result.Evidence, controlEvidence(record, facetID, policyID, ControlStatePassing, passReason))
			continue
		}
		result.Failing++
		result.FailEntityIDs[record.ID] = struct{}{}
		result.Evidence = append(result.Evidence, controlEvidence(record, facetID, policyID, ControlStateFailing, failReason))
	}
	result.Status = summarizePolicyStatus(result, unknown, len(records))
	return result
}

func (e *graphComplianceEvaluator) evaluateBucketPublicPolicy(policyID, provider string) policyEvaluation {
	records := e.entityRecords(provider, graph.NodeKindBucket)
	result := policyEvaluation{
		PolicyID:      policyID,
		Supported:     true,
		Source:        ControlEvaluationSourceGraph,
		FailEntityIDs: make(map[string]struct{}),
		PassEntityIDs: make(map[string]struct{}),
	}
	if len(records) == 0 {
		result.Status = ControlStateNotApplicable
		return result
	}
	unknown := 0
	for _, record := range records {
		facet, ok := entityFacet(record, "bucket_public_access")
		if !ok {
			unknown++
			continue
		}
		publicAccess, publicKnown := boolField(facet.Fields, "public_access")
		allUsers, allUsersKnown := boolField(facet.Fields, "all_users_access")
		allAuthenticated, authKnown := boolField(facet.Fields, "all_authenticated_users_access")
		if !publicKnown && !allUsersKnown && !authKnown {
			unknown++
			continue
		}
		result.Applicable++
		public := (publicKnown && publicAccess) || (allUsersKnown && allUsers) || (authKnown && allAuthenticated)
		if public {
			result.Failing++
			result.FailEntityIDs[record.ID] = struct{}{}
			result.Evidence = append(result.Evidence, controlEvidence(record, "bucket_public_access", policyID, ControlStateFailing, "Bucket policy or access posture allows public principals"))
			continue
		}
		result.Passing++
		result.PassEntityIDs[record.ID] = struct{}{}
		result.Evidence = append(result.Evidence, controlEvidence(record, "bucket_public_access", policyID, ControlStatePassing, "Bucket policy does not expose public principals"))
	}
	result.Status = summarizePolicyStatus(result, unknown, len(records))
	return result
}

func (e *graphComplianceEvaluator) evaluateBucketVersioning(policyID, provider string) policyEvaluation {
	records := e.entityRecords(provider, graph.NodeKindBucket)
	result := policyEvaluation{
		PolicyID:      policyID,
		Supported:     true,
		Source:        ControlEvaluationSourceGraph,
		FailEntityIDs: make(map[string]struct{}),
		PassEntityIDs: make(map[string]struct{}),
	}
	if len(records) == 0 {
		result.Status = ControlStateNotApplicable
		return result
	}
	unknown := 0
	for _, record := range records {
		facet, ok := entityFacet(record, "bucket_versioning")
		if !ok {
			unknown++
			continue
		}
		status := strings.TrimSpace(strings.ToLower(stringField(facet.Fields, "versioning_status")))
		if status == "" {
			unknown++
			continue
		}
		result.Applicable++
		if status == "enabled" || status == "on" {
			result.Passing++
			result.PassEntityIDs[record.ID] = struct{}{}
			result.Evidence = append(result.Evidence, controlEvidence(record, "bucket_versioning", policyID, ControlStatePassing, "Bucket versioning is enabled"))
			continue
		}
		result.Failing++
		result.FailEntityIDs[record.ID] = struct{}{}
		result.Evidence = append(result.Evidence, controlEvidence(record, "bucket_versioning", policyID, ControlStateFailing, "Bucket versioning is not enabled"))
	}
	result.Status = summarizePolicyStatus(result, unknown, len(records))
	return result
}

func (e *graphComplianceEvaluator) evaluatePropertyBoolPolicy(policyID, provider string, kinds []graph.NodeKind, keys []string, expected bool, facetID, passReason, failReason string) policyEvaluation {
	records := e.entityRecords(provider, kinds...)
	result := policyEvaluation{
		PolicyID:      policyID,
		Supported:     true,
		Source:        ControlEvaluationSourceGraph,
		FailEntityIDs: make(map[string]struct{}),
		PassEntityIDs: make(map[string]struct{}),
	}
	if len(records) == 0 {
		result.Status = ControlStateNotApplicable
		return result
	}
	unknown := 0
	for _, record := range records {
		value, ok := firstBool(record.Properties, keys...)
		if !ok {
			unknown++
			continue
		}
		result.Applicable++
		if value == expected {
			result.Passing++
			result.PassEntityIDs[record.ID] = struct{}{}
			result.Evidence = append(result.Evidence, controlEvidence(record, facetID, policyID, ControlStatePassing, passReason))
			continue
		}
		result.Failing++
		result.FailEntityIDs[record.ID] = struct{}{}
		result.Evidence = append(result.Evidence, controlEvidence(record, facetID, policyID, ControlStateFailing, failReason))
	}
	result.Status = summarizePolicyStatus(result, unknown, len(records))
	return result
}

func (e *graphComplianceEvaluator) evaluateSensitiveDataEncryption(policyID string) policyEvaluation {
	records := e.entityRecords("", graph.NodeKindBucket, graph.NodeKindDatabase, graph.NodeKindSecret, graph.NodeKindService)
	result := policyEvaluation{
		PolicyID:      policyID,
		Supported:     true,
		Source:        ControlEvaluationSourceGraph,
		FailEntityIDs: make(map[string]struct{}),
		PassEntityIDs: make(map[string]struct{}),
	}
	if len(records) == 0 {
		result.Status = ControlStateNotApplicable
		return result
	}
	unknown := 0
	for _, record := range records {
		sensitive, sensitiveKnown := sensitiveDataState(record)
		if !sensitiveKnown || !sensitive {
			continue
		}
		encrypted, encryptionKnown, facetID := encryptionState(record)
		if !encryptionKnown {
			unknown++
			continue
		}
		result.Applicable++
		if encrypted {
			result.Passing++
			result.PassEntityIDs[record.ID] = struct{}{}
			result.Evidence = append(result.Evidence, controlEvidence(record, facetID, policyID, ControlStatePassing, "Sensitive data asset is encrypted"))
			continue
		}
		result.Failing++
		result.FailEntityIDs[record.ID] = struct{}{}
		result.Evidence = append(result.Evidence, controlEvidence(record, facetID, policyID, ControlStateFailing, "Sensitive data asset is not encrypted"))
	}
	result.Status = summarizePolicyStatus(result, unknown, len(records))
	return result
}

func (e *graphComplianceEvaluator) evaluateSensitiveDataExposure(policyID string) policyEvaluation {
	records := e.entityRecords("", graph.NodeKindBucket, graph.NodeKindDatabase, graph.NodeKindService, graph.NodeKindSecret, graph.NodeKindFunction)
	result := policyEvaluation{
		PolicyID:      policyID,
		Supported:     true,
		Source:        ControlEvaluationSourceGraph,
		FailEntityIDs: make(map[string]struct{}),
		PassEntityIDs: make(map[string]struct{}),
	}
	if len(records) == 0 {
		result.Status = ControlStateNotApplicable
		return result
	}
	unknown := 0
	for _, record := range records {
		sensitive, sensitiveKnown := sensitiveDataState(record)
		if !sensitiveKnown || !sensitive {
			continue
		}
		public, publicKnown, facetID := publicExposureState(record)
		if !publicKnown {
			unknown++
			continue
		}
		result.Applicable++
		if public {
			result.Failing++
			result.FailEntityIDs[record.ID] = struct{}{}
			result.Evidence = append(result.Evidence, controlEvidence(record, facetID, policyID, ControlStateFailing, "Sensitive data asset is publicly exposed"))
			continue
		}
		result.Passing++
		result.PassEntityIDs[record.ID] = struct{}{}
		result.Evidence = append(result.Evidence, controlEvidence(record, facetID, policyID, ControlStatePassing, "Sensitive data asset is not publicly exposed"))
	}
	result.Status = summarizePolicyStatus(result, unknown, len(records))
	return result
}

func (e *graphComplianceEvaluator) evaluateServiceAccountAdminPrivileges(policyID string) policyEvaluation {
	records := e.entityRecords("gcp", graph.NodeKindServiceAccount)
	result := policyEvaluation{
		PolicyID:      policyID,
		Supported:     true,
		Source:        ControlEvaluationSourceGraph,
		FailEntityIDs: make(map[string]struct{}),
		PassEntityIDs: make(map[string]struct{}),
	}
	if len(records) == 0 {
		result.Status = ControlStateNotApplicable
		return result
	}
	unknown := 0
	for _, record := range records {
		hasAdmin, okAdmin := firstBool(record.Properties, "has_admin_role")
		hasHighPriv, okHigh := firstBool(record.Properties, "has_high_privilege")
		if !okAdmin && !okHigh {
			unknown++
			continue
		}
		result.Applicable++
		if hasAdmin || hasHighPriv {
			result.Failing++
			result.FailEntityIDs[record.ID] = struct{}{}
			result.Evidence = append(result.Evidence, controlEvidence(record, "", policyID, ControlStateFailing, "Service account has admin or high-privilege roles"))
			continue
		}
		result.Passing++
		result.PassEntityIDs[record.ID] = struct{}{}
		result.Evidence = append(result.Evidence, controlEvidence(record, "", policyID, ControlStatePassing, "Service account does not have admin or high-privilege roles"))
	}
	result.Status = summarizePolicyStatus(result, unknown, len(records))
	return result
}

func (e *graphComplianceEvaluator) evaluateServiceAccountKeyRotation(policyID string) policyEvaluation {
	records := e.entityRecords("gcp", graph.NodeKindServiceAccount)
	result := policyEvaluation{
		PolicyID:      policyID,
		Supported:     true,
		Source:        ControlEvaluationSourceGraph,
		FailEntityIDs: make(map[string]struct{}),
		PassEntityIDs: make(map[string]struct{}),
	}
	if len(records) == 0 {
		result.Status = ControlStateNotApplicable
		return result
	}
	unknown := 0
	for _, record := range records {
		hasKeys, okKeys := firstBool(record.Properties, "has_access_keys")
		oldestKeyAge, okAge := firstInt(record.Properties, "oldest_key_age_days")
		if !okKeys && !okAge {
			unknown++
			continue
		}
		if !hasKeys {
			result.Applicable++
			result.Passing++
			result.PassEntityIDs[record.ID] = struct{}{}
			result.Evidence = append(result.Evidence, controlEvidence(record, "", policyID, ControlStatePassing, "Service account has no user-managed keys"))
			continue
		}
		result.Applicable++
		if okAge && oldestKeyAge <= 90 {
			result.Passing++
			result.PassEntityIDs[record.ID] = struct{}{}
			result.Evidence = append(result.Evidence, controlEvidence(record, "", policyID, ControlStatePassing, "Service account keys are rotated within 90 days"))
			continue
		}
		result.Failing++
		result.FailEntityIDs[record.ID] = struct{}{}
		result.Evidence = append(result.Evidence, controlEvidence(record, "", policyID, ControlStateFailing, "Service account keys are older than 90 days"))
	}
	result.Status = summarizePolicyStatus(result, unknown, len(records))
	return result
}

func (e *graphComplianceEvaluator) evaluateServiceAccountMinimizeKeys(policyID string) policyEvaluation {
	records := e.entityRecords("gcp", graph.NodeKindServiceAccount)
	result := policyEvaluation{
		PolicyID:      policyID,
		Supported:     true,
		Source:        ControlEvaluationSourceGraph,
		FailEntityIDs: make(map[string]struct{}),
		PassEntityIDs: make(map[string]struct{}),
	}
	if len(records) == 0 {
		result.Status = ControlStateNotApplicable
		return result
	}
	unknown := 0
	for _, record := range records {
		hasKeys, ok := firstBool(record.Properties, "has_access_keys")
		if !ok {
			unknown++
			continue
		}
		result.Applicable++
		if hasKeys {
			result.Failing++
			result.FailEntityIDs[record.ID] = struct{}{}
			result.Evidence = append(result.Evidence, controlEvidence(record, "", policyID, ControlStateFailing, "Service account uses user-managed keys"))
			continue
		}
		result.Passing++
		result.PassEntityIDs[record.ID] = struct{}{}
		result.Evidence = append(result.Evidence, controlEvidence(record, "", policyID, ControlStatePassing, "Service account has no user-managed keys"))
	}
	result.Status = summarizePolicyStatus(result, unknown, len(records))
	return result
}

func (e *graphComplianceEvaluator) entityRecords(provider string, kinds ...graph.NodeKind) []graph.EntityRecord {
	sortKinds := append([]graph.NodeKind(nil), kinds...)
	sort.Slice(sortKinds, func(i, j int) bool { return sortKinds[i] < sortKinds[j] })
	parts := []string{provider}
	for _, kind := range sortKinds {
		parts = append(parts, string(kind))
	}
	cacheKey := strings.Join(parts, "|")
	if cached, ok := e.entityCache[cacheKey]; ok {
		return cached
	}
	kindSet := make(map[graph.NodeKind]struct{}, len(sortKinds))
	for _, kind := range sortKinds {
		kindSet[kind] = struct{}{}
	}
	records := make([]graph.EntityRecord, 0)
	if e.graph != nil {
		for _, node := range e.graph.GetAllNodesBitemporal(e.validAt, e.recordedAt) {
			if node == nil {
				continue
			}
			if provider != "" && !strings.EqualFold(strings.TrimSpace(node.Provider), provider) {
				continue
			}
			if len(kindSet) > 0 {
				if _, ok := kindSet[node.Kind]; !ok {
					continue
				}
			}
			record, ok := graph.GetEntityRecord(e.graph, node.ID, e.validAt, e.recordedAt)
			if !ok {
				continue
			}
			records = append(records, record)
		}
	}
	sort.Slice(records, func(i, j int) bool { return records[i].ID < records[j].ID })
	e.entityCache[cacheKey] = records
	return records
}

func summarizePolicyStatus(result policyEvaluation, unknown, totalRecords int) string {
	switch {
	case result.Failing > 0:
		return ControlStateFailing
	case result.Applicable == 0 && totalRecords == 0:
		return ControlStateNotApplicable
	case result.Applicable == 0 && unknown > 0:
		return ControlStateUnknown
	case result.Applicable == 0:
		return ControlStateNotApplicable
	case unknown > 0:
		if result.Passing > 0 {
			return ControlStatePartial
		}
		return ControlStateUnknown
	case result.Passing > 0:
		return ControlStatePassing
	default:
		return ControlStateUnknown
	}
}

func controlEvidence(record graph.EntityRecord, facetID, policyID, status, reason string) ControlEvidence {
	return ControlEvidence{
		EntityID:   record.ID,
		EntityKind: string(record.Kind),
		EntityName: record.Name,
		FacetID:    facetID,
		PolicyID:   policyID,
		Status:     status,
		Reason:     reason,
	}
}

func entityFacet(record graph.EntityRecord, facetID string) (graph.EntityFacetRecord, bool) {
	for _, facet := range record.Facets {
		if facet.ID == facetID {
			return facet, true
		}
	}
	return graph.EntityFacetRecord{}, false
}

func sensitiveDataState(record graph.EntityRecord) (bool, bool) {
	facet, ok := entityFacet(record, "data_sensitivity")
	if !ok {
		return false, false
	}
	classification := strings.TrimSpace(strings.ToLower(stringField(facet.Fields, "classification")))
	if classification != "" && classification != "none" {
		return true, true
	}
	for _, field := range []string{"contains_pii", "contains_phi", "contains_pci", "contains_secrets"} {
		if value, ok := boolField(facet.Fields, field); ok && value {
			return true, true
		}
	}
	for _, field := range []string{"contains_pii", "contains_phi", "contains_pci", "contains_secrets"} {
		if _, ok := boolField(facet.Fields, field); ok {
			return false, true
		}
	}
	return false, false
}

func encryptionState(record graph.EntityRecord) (bool, bool, string) {
	if facet, ok := entityFacet(record, "bucket_encryption"); ok {
		if value, ok := boolField(facet.Fields, "encrypted"); ok {
			return value, true, facet.ID
		}
	}
	if value, ok := firstBool(record.Properties, "encrypted", "storage_encrypted", "kms_encrypted"); ok {
		return value, true, ""
	}
	return false, false, ""
}

func publicExposureState(record graph.EntityRecord) (bool, bool, string) {
	if facet, ok := entityFacet(record, "bucket_public_access"); ok {
		if value, ok := boolField(facet.Fields, "public_access"); ok {
			return value, true, facet.ID
		}
	}
	if facet, ok := entityFacet(record, "exposure"); ok {
		if value, ok := boolField(facet.Fields, "public_access"); ok {
			return value, true, facet.ID
		}
		if value, ok := boolField(facet.Fields, "internet_exposed"); ok {
			return value, true, facet.ID
		}
	}
	if value, ok := firstBool(record.Properties, "public", "public_access", "publicly_accessible", "internet_accessible"); ok {
		return value, true, ""
	}
	return false, false, ""
}

func boolField(fields map[string]any, key string) (bool, bool) {
	if fields == nil {
		return false, false
	}
	value, ok := fields[key]
	if !ok {
		return false, false
	}
	switch typed := value.(type) {
	case bool:
		return typed, true
	case string:
		switch strings.TrimSpace(strings.ToLower(typed)) {
		case "true", "enabled", "on", "yes":
			return true, true
		case "false", "disabled", "off", "no":
			return false, true
		}
	}
	return false, false
}

func stringField(fields map[string]any, key string) string {
	if fields == nil {
		return ""
	}
	if value, ok := fields[key]; ok {
		switch typed := value.(type) {
		case string:
			return typed
		case fmt.Stringer:
			return typed.String()
		}
	}
	return ""
}

func firstBool(fields map[string]any, keys ...string) (bool, bool) {
	for _, key := range keys {
		if value, ok := boolField(fields, key); ok {
			return value, true
		}
	}
	return false, false
}

func firstInt(fields map[string]any, keys ...string) (int, bool) {
	for _, key := range keys {
		value, ok := fields[key]
		if !ok {
			continue
		}
		switch typed := value.(type) {
		case int:
			return typed, true
		case int32:
			return int(typed), true
		case int64:
			return int(typed), true
		case float64:
			return int(typed), true
		case float32:
			return int(typed), true
		}
	}
	return 0, false
}

func unionStringSets(sets ...map[string]struct{}) map[string]struct{} {
	out := make(map[string]struct{})
	for _, set := range sets {
		for key := range set {
			out[key] = struct{}{}
		}
	}
	return out
}

func cloneFindingCounts(src map[string]int) map[string]int {
	if len(src) == 0 {
		return map[string]int{}
	}
	dst := make(map[string]int, len(src))
	for key, value := range src {
		dst[key] = value
	}
	return dst
}
