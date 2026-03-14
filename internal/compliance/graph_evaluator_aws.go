package compliance

import (
	"strings"

	"github.com/evalops/cerebro/internal/graph"
)

func (e *graphComplianceEvaluator) evaluateFacetBoolPolicy(policyID, provider string, kinds []graph.NodeKind, facetID, field string, expected bool, passReason, failReason string) policyEvaluation {
	records := e.entityRecords(provider, kinds...)
	result := newGraphPolicyEvaluation(policyID)
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
	result := newGraphPolicyEvaluation(policyID)
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
	result := newGraphPolicyEvaluation(policyID)
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
	result := newGraphPolicyEvaluation(policyID)
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
