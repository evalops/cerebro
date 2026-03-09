package app

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/evalops/cerebro/internal/graph"
)

func (a *App) toolCerebroRecordObservation(_ context.Context, args json.RawMessage) (string, error) {
	g, err := a.requireSecurityGraph()
	if err != nil {
		return "", err
	}

	var req struct {
		ID            string         `json:"id"`
		EntityID      string         `json:"entity_id"`
		Observation   string         `json:"observation"`
		Summary       string         `json:"summary"`
		SourceSystem  string         `json:"source_system"`
		SourceEventID string         `json:"source_event_id"`
		ObservedAt    time.Time      `json:"observed_at"`
		ValidFrom     time.Time      `json:"valid_from"`
		ValidTo       *time.Time     `json:"valid_to"`
		Confidence    float64        `json:"confidence"`
		Metadata      map[string]any `json:"metadata"`
	}
	if err := decodeToolArgs(args, &req); err != nil {
		return "", err
	}

	req.EntityID = strings.TrimSpace(req.EntityID)
	req.Observation = strings.TrimSpace(req.Observation)
	req.Summary = strings.TrimSpace(req.Summary)
	if req.EntityID == "" {
		return "", fmt.Errorf("entity_id is required")
	}
	if req.Observation == "" {
		return "", fmt.Errorf("observation is required")
	}
	if _, ok := g.GetNode(req.EntityID); !ok {
		return "", fmt.Errorf("entity not found: %s", req.EntityID)
	}

	observedAt, validFrom, validTo, sourceSystem, sourceEventID, confidence := normalizeToolGraphWriteMetadata(
		req.ObservedAt,
		req.ValidFrom,
		req.ValidTo,
		req.SourceSystem,
		req.SourceEventID,
		req.Confidence,
	)

	observationID := strings.TrimSpace(req.ID)
	if observationID == "" {
		observationID = fmt.Sprintf("evidence:observation:%d", observedAt.UnixNano())
	}

	properties := cloneToolJSONMap(req.Metadata)
	properties["evidence_type"] = req.Observation
	properties["detail"] = firstNonEmpty(req.Summary, req.Observation)
	applyToolGraphWriteMetadata(properties, observedAt, validFrom, validTo, sourceSystem, sourceEventID, confidence)

	g.AddNode(&graph.Node{
		ID:         observationID,
		Kind:       graph.NodeKindEvidence,
		Name:       firstNonEmpty(req.Observation, req.Summary, observationID),
		Provider:   sourceSystem,
		Properties: properties,
		Risk:       graph.RiskNone,
	})

	edgeProperties := map[string]any{
		"source_system":   sourceSystem,
		"source_event_id": sourceEventID,
		"observed_at":     observedAt.Format(time.RFC3339),
		"valid_from":      validFrom.Format(time.RFC3339),
		"confidence":      confidence,
	}
	if validTo != nil {
		edgeProperties["valid_to"] = validTo.Format(time.RFC3339)
	}
	g.AddEdge(&graph.Edge{
		ID:         fmt.Sprintf("%s->%s:%s", observationID, req.EntityID, graph.EdgeKindTargets),
		Source:     observationID,
		Target:     req.EntityID,
		Kind:       graph.EdgeKindTargets,
		Effect:     graph.EdgeEffectAllow,
		Properties: edgeProperties,
	})

	return marshalToolResponse(map[string]any{
		"observation_id": observationID,
		"entity_id":      req.EntityID,
		"observed_at":    observedAt,
	})
}

func (a *App) toolCerebroAnnotateEntity(_ context.Context, args json.RawMessage) (string, error) {
	g, err := a.requireSecurityGraph()
	if err != nil {
		return "", err
	}

	var req struct {
		EntityID      string         `json:"entity_id"`
		Annotation    string         `json:"annotation"`
		Tags          []string       `json:"tags"`
		SourceSystem  string         `json:"source_system"`
		SourceEventID string         `json:"source_event_id"`
		ObservedAt    time.Time      `json:"observed_at"`
		ValidFrom     time.Time      `json:"valid_from"`
		ValidTo       *time.Time     `json:"valid_to"`
		Confidence    float64        `json:"confidence"`
		Metadata      map[string]any `json:"metadata"`
	}
	if err := decodeToolArgs(args, &req); err != nil {
		return "", err
	}

	req.EntityID = strings.TrimSpace(req.EntityID)
	req.Annotation = strings.TrimSpace(req.Annotation)
	if req.EntityID == "" {
		return "", fmt.Errorf("entity_id is required")
	}
	if req.Annotation == "" {
		return "", fmt.Errorf("annotation is required")
	}

	entity, ok := g.GetNode(req.EntityID)
	if !ok || entity == nil {
		return "", fmt.Errorf("entity not found: %s", req.EntityID)
	}

	observedAt, validFrom, validTo, sourceSystem, sourceEventID, confidence := normalizeToolGraphWriteMetadata(
		req.ObservedAt,
		req.ValidFrom,
		req.ValidTo,
		req.SourceSystem,
		req.SourceEventID,
		req.Confidence,
	)

	annotationID := fmt.Sprintf("annotation:%s:%d", req.EntityID, observedAt.UnixNano())
	properties := cloneToolJSONMap(entity.Properties)
	existing := toolAnnotationsFromValue(properties["annotations"])
	entry := map[string]any{
		"id":              annotationID,
		"annotation":      req.Annotation,
		"tags":            normalizeToolStringSlice(req.Tags),
		"source_system":   sourceSystem,
		"source_event_id": sourceEventID,
		"observed_at":     observedAt.Format(time.RFC3339),
		"valid_from":      validFrom.Format(time.RFC3339),
		"confidence":      confidence,
	}
	if validTo != nil {
		entry["valid_to"] = validTo.Format(time.RFC3339)
	}
	if len(req.Metadata) > 0 {
		entry["metadata"] = cloneToolJSONMap(req.Metadata)
	}
	existing = append(existing, entry)
	properties["annotations"] = existing
	applyToolGraphWriteMetadata(properties, observedAt, validFrom, validTo, sourceSystem, sourceEventID, confidence)

	entity.Properties = properties
	g.AddNode(entity)

	return marshalToolResponse(map[string]any{
		"annotation_id": annotationID,
		"entity_id":     req.EntityID,
		"count":         len(existing),
	})
}

func (a *App) toolCerebroRecordDecision(_ context.Context, args json.RawMessage) (string, error) {
	g, err := a.requireSecurityGraph()
	if err != nil {
		return "", err
	}

	var req struct {
		ID            string         `json:"id"`
		DecisionType  string         `json:"decision_type"`
		Status        string         `json:"status"`
		MadeBy        string         `json:"made_by"`
		Rationale     string         `json:"rationale"`
		TargetIDs     []string       `json:"target_ids"`
		EvidenceIDs   []string       `json:"evidence_ids"`
		ActionIDs     []string       `json:"action_ids"`
		SourceSystem  string         `json:"source_system"`
		SourceEventID string         `json:"source_event_id"`
		ObservedAt    time.Time      `json:"observed_at"`
		ValidFrom     time.Time      `json:"valid_from"`
		ValidTo       *time.Time     `json:"valid_to"`
		Confidence    float64        `json:"confidence"`
		Metadata      map[string]any `json:"metadata"`
	}
	if err := decodeToolArgs(args, &req); err != nil {
		return "", err
	}

	req.DecisionType = strings.TrimSpace(req.DecisionType)
	req.Status = strings.TrimSpace(req.Status)
	req.MadeBy = strings.TrimSpace(req.MadeBy)
	req.Rationale = strings.TrimSpace(req.Rationale)
	if req.DecisionType == "" {
		return "", fmt.Errorf("decision_type is required")
	}

	targetIDs := uniqueToolNormalizedIDs(req.TargetIDs)
	if len(targetIDs) == 0 {
		return "", fmt.Errorf("target_ids requires at least one target")
	}
	for _, targetID := range targetIDs {
		if _, ok := g.GetNode(targetID); !ok {
			return "", fmt.Errorf("target not found: %s", targetID)
		}
	}

	observedAt, validFrom, validTo, sourceSystem, sourceEventID, confidence := normalizeToolGraphWriteMetadata(
		req.ObservedAt,
		req.ValidFrom,
		req.ValidTo,
		req.SourceSystem,
		req.SourceEventID,
		req.Confidence,
	)

	decisionID := strings.TrimSpace(req.ID)
	if decisionID == "" {
		decisionID = fmt.Sprintf("decision:%d", observedAt.UnixNano())
	}

	properties := cloneToolJSONMap(req.Metadata)
	properties["decision_type"] = req.DecisionType
	properties["status"] = firstNonEmpty(req.Status, "proposed")
	properties["made_at"] = observedAt.Format(time.RFC3339)
	properties["made_by"] = req.MadeBy
	properties["rationale"] = req.Rationale
	applyToolGraphWriteMetadata(properties, observedAt, validFrom, validTo, sourceSystem, sourceEventID, confidence)

	g.AddNode(&graph.Node{
		ID:         decisionID,
		Kind:       graph.NodeKindDecision,
		Name:       firstNonEmpty(req.DecisionType, decisionID),
		Provider:   sourceSystem,
		Properties: properties,
		Risk:       graph.RiskNone,
	})

	for _, targetID := range targetIDs {
		g.AddEdge(&graph.Edge{
			ID:     fmt.Sprintf("%s->%s:%s", decisionID, targetID, graph.EdgeKindTargets),
			Source: decisionID,
			Target: targetID,
			Kind:   graph.EdgeKindTargets,
			Effect: graph.EdgeEffectAllow,
			Properties: map[string]any{
				"source_system":   sourceSystem,
				"source_event_id": sourceEventID,
				"observed_at":     observedAt.Format(time.RFC3339),
				"valid_from":      validFrom.Format(time.RFC3339),
				"confidence":      confidence,
			},
		})
	}
	for _, evidenceID := range uniqueToolNormalizedIDs(req.EvidenceIDs) {
		if _, ok := g.GetNode(evidenceID); !ok {
			continue
		}
		g.AddEdge(&graph.Edge{
			ID:     fmt.Sprintf("%s->%s:%s", decisionID, evidenceID, graph.EdgeKindBasedOn),
			Source: decisionID,
			Target: evidenceID,
			Kind:   graph.EdgeKindBasedOn,
			Effect: graph.EdgeEffectAllow,
			Properties: map[string]any{
				"source_system":   sourceSystem,
				"source_event_id": sourceEventID,
				"observed_at":     observedAt.Format(time.RFC3339),
				"valid_from":      validFrom.Format(time.RFC3339),
				"confidence":      confidence,
			},
		})
	}
	for _, actionID := range uniqueToolNormalizedIDs(req.ActionIDs) {
		if _, ok := g.GetNode(actionID); !ok {
			continue
		}
		g.AddEdge(&graph.Edge{
			ID:     fmt.Sprintf("%s->%s:%s", decisionID, actionID, graph.EdgeKindExecutedBy),
			Source: decisionID,
			Target: actionID,
			Kind:   graph.EdgeKindExecutedBy,
			Effect: graph.EdgeEffectAllow,
			Properties: map[string]any{
				"source_system":   sourceSystem,
				"source_event_id": sourceEventID,
				"observed_at":     observedAt.Format(time.RFC3339),
				"valid_from":      validFrom.Format(time.RFC3339),
				"confidence":      confidence,
			},
		})
	}

	return marshalToolResponse(map[string]any{
		"decision_id":  decisionID,
		"target_count": len(targetIDs),
	})
}

func (a *App) toolCerebroRecordOutcome(_ context.Context, args json.RawMessage) (string, error) {
	g, err := a.requireSecurityGraph()
	if err != nil {
		return "", err
	}

	var req struct {
		ID            string         `json:"id"`
		DecisionID    string         `json:"decision_id"`
		OutcomeType   string         `json:"outcome_type"`
		Verdict       string         `json:"verdict"`
		ImpactScore   float64        `json:"impact_score"`
		TargetIDs     []string       `json:"target_ids"`
		SourceSystem  string         `json:"source_system"`
		SourceEventID string         `json:"source_event_id"`
		ObservedAt    time.Time      `json:"observed_at"`
		ValidFrom     time.Time      `json:"valid_from"`
		ValidTo       *time.Time     `json:"valid_to"`
		Confidence    float64        `json:"confidence"`
		Metadata      map[string]any `json:"metadata"`
	}
	if err := decodeToolArgs(args, &req); err != nil {
		return "", err
	}

	req.DecisionID = strings.TrimSpace(req.DecisionID)
	req.OutcomeType = strings.TrimSpace(req.OutcomeType)
	req.Verdict = strings.TrimSpace(req.Verdict)
	if req.DecisionID == "" {
		return "", fmt.Errorf("decision_id is required")
	}
	if req.OutcomeType == "" || req.Verdict == "" {
		return "", fmt.Errorf("outcome_type and verdict are required")
	}
	if _, ok := g.GetNode(req.DecisionID); !ok {
		return "", fmt.Errorf("decision not found: %s", req.DecisionID)
	}

	observedAt, validFrom, validTo, sourceSystem, sourceEventID, confidence := normalizeToolGraphWriteMetadata(
		req.ObservedAt,
		req.ValidFrom,
		req.ValidTo,
		req.SourceSystem,
		req.SourceEventID,
		req.Confidence,
	)

	outcomeID := strings.TrimSpace(req.ID)
	if outcomeID == "" {
		outcomeID = fmt.Sprintf("outcome:%d", observedAt.UnixNano())
	}

	properties := cloneToolJSONMap(req.Metadata)
	properties["outcome_type"] = req.OutcomeType
	properties["verdict"] = req.Verdict
	properties["impact_score"] = req.ImpactScore
	applyToolGraphWriteMetadata(properties, observedAt, validFrom, validTo, sourceSystem, sourceEventID, confidence)

	g.AddNode(&graph.Node{
		ID:         outcomeID,
		Kind:       graph.NodeKindOutcome,
		Name:       firstNonEmpty(req.OutcomeType, outcomeID),
		Provider:   sourceSystem,
		Properties: properties,
		Risk:       graph.RiskNone,
	})
	g.AddEdge(&graph.Edge{
		ID:     fmt.Sprintf("%s->%s:%s", outcomeID, req.DecisionID, graph.EdgeKindEvaluates),
		Source: outcomeID,
		Target: req.DecisionID,
		Kind:   graph.EdgeKindEvaluates,
		Effect: graph.EdgeEffectAllow,
		Properties: map[string]any{
			"source_system":   sourceSystem,
			"source_event_id": sourceEventID,
			"observed_at":     observedAt.Format(time.RFC3339),
			"valid_from":      validFrom.Format(time.RFC3339),
			"confidence":      confidence,
		},
	})

	targetIDs := uniqueToolNormalizedIDs(req.TargetIDs)
	for _, targetID := range targetIDs {
		if _, ok := g.GetNode(targetID); !ok {
			continue
		}
		g.AddEdge(&graph.Edge{
			ID:     fmt.Sprintf("%s->%s:%s", outcomeID, targetID, graph.EdgeKindTargets),
			Source: outcomeID,
			Target: targetID,
			Kind:   graph.EdgeKindTargets,
			Effect: graph.EdgeEffectAllow,
			Properties: map[string]any{
				"source_system":   sourceSystem,
				"source_event_id": sourceEventID,
				"observed_at":     observedAt.Format(time.RFC3339),
				"valid_from":      validFrom.Format(time.RFC3339),
				"confidence":      confidence,
			},
		})
	}

	return marshalToolResponse(map[string]any{
		"outcome_id":   outcomeID,
		"decision_id":  req.DecisionID,
		"target_count": len(targetIDs),
	})
}

func (a *App) toolCerebroResolveIdentity(_ context.Context, args json.RawMessage) (string, error) {
	g, err := a.requireSecurityGraph()
	if err != nil {
		return "", err
	}

	var req struct {
		AliasID           string    `json:"alias_id"`
		SourceSystem      string    `json:"source_system"`
		SourceEventID     string    `json:"source_event_id"`
		ExternalID        string    `json:"external_id"`
		AliasType         string    `json:"alias_type"`
		CanonicalHint     string    `json:"canonical_hint"`
		Email             string    `json:"email"`
		Name              string    `json:"name"`
		ObservedAt        time.Time `json:"observed_at"`
		Confidence        float64   `json:"confidence"`
		AutoLinkThreshold float64   `json:"auto_link_threshold"`
		SuggestThreshold  float64   `json:"suggest_threshold"`
	}
	if err := decodeToolArgs(args, &req); err != nil {
		return "", err
	}

	result, err := graph.ResolveIdentityAlias(g, graph.IdentityAliasAssertion{
		AliasID:       strings.TrimSpace(req.AliasID),
		SourceSystem:  strings.TrimSpace(req.SourceSystem),
		SourceEventID: strings.TrimSpace(req.SourceEventID),
		ExternalID:    strings.TrimSpace(req.ExternalID),
		AliasType:     strings.TrimSpace(req.AliasType),
		CanonicalHint: strings.TrimSpace(req.CanonicalHint),
		Email:         strings.TrimSpace(req.Email),
		Name:          strings.TrimSpace(req.Name),
		ObservedAt:    req.ObservedAt,
		Confidence:    req.Confidence,
	}, graph.IdentityResolutionOptions{
		AutoLinkThreshold: req.AutoLinkThreshold,
		SuggestThreshold:  req.SuggestThreshold,
	})
	if err != nil {
		return "", err
	}
	return marshalToolResponse(result)
}

func (a *App) toolCerebroSplitIdentity(_ context.Context, args json.RawMessage) (string, error) {
	g, err := a.requireSecurityGraph()
	if err != nil {
		return "", err
	}

	var req struct {
		AliasNodeID     string    `json:"alias_node_id"`
		CanonicalNodeID string    `json:"canonical_node_id"`
		Reason          string    `json:"reason"`
		SourceSystem    string    `json:"source_system"`
		SourceEventID   string    `json:"source_event_id"`
		ObservedAt      time.Time `json:"observed_at"`
	}
	if err := decodeToolArgs(args, &req); err != nil {
		return "", err
	}

	removed, err := graph.SplitIdentityAlias(
		g,
		strings.TrimSpace(req.AliasNodeID),
		strings.TrimSpace(req.CanonicalNodeID),
		strings.TrimSpace(req.Reason),
		strings.TrimSpace(req.SourceSystem),
		strings.TrimSpace(req.SourceEventID),
		req.ObservedAt,
	)
	if err != nil {
		return "", err
	}
	return marshalToolResponse(map[string]any{
		"removed":           removed,
		"alias_node_id":     strings.TrimSpace(req.AliasNodeID),
		"canonical_node_id": strings.TrimSpace(req.CanonicalNodeID),
	})
}

func (a *App) toolCerebroIdentityReview(_ context.Context, args json.RawMessage) (string, error) {
	g, err := a.requireSecurityGraph()
	if err != nil {
		return "", err
	}

	var req struct {
		AliasNodeID     string    `json:"alias_node_id"`
		CanonicalNodeID string    `json:"canonical_node_id"`
		Verdict         string    `json:"verdict"`
		Reviewer        string    `json:"reviewer"`
		Reason          string    `json:"reason"`
		SourceSystem    string    `json:"source_system"`
		SourceEventID   string    `json:"source_event_id"`
		ObservedAt      time.Time `json:"observed_at"`
		Confidence      float64   `json:"confidence"`
	}
	if err := decodeToolArgs(args, &req); err != nil {
		return "", err
	}

	record, err := graph.ReviewIdentityAlias(g, graph.IdentityReviewDecision{
		AliasNodeID:     strings.TrimSpace(req.AliasNodeID),
		CanonicalNodeID: strings.TrimSpace(req.CanonicalNodeID),
		Verdict:         strings.TrimSpace(req.Verdict),
		Reviewer:        strings.TrimSpace(req.Reviewer),
		Reason:          strings.TrimSpace(req.Reason),
		SourceSystem:    strings.TrimSpace(req.SourceSystem),
		SourceEventID:   strings.TrimSpace(req.SourceEventID),
		ObservedAt:      req.ObservedAt,
		Confidence:      req.Confidence,
	})
	if err != nil {
		return "", err
	}
	return marshalToolResponse(record)
}

func (a *App) toolCerebroIdentityCalibration(_ context.Context, args json.RawMessage) (string, error) {
	g, err := a.requireSecurityGraph()
	if err != nil {
		return "", err
	}

	var req struct {
		SuggestThreshold float64 `json:"suggest_threshold"`
		QueueLimit       int     `json:"queue_limit"`
		IncludeQueue     *bool   `json:"include_queue"`
	}
	if err := decodeToolArgs(args, &req); err != nil {
		return "", err
	}
	if req.SuggestThreshold < 0 || req.SuggestThreshold > 1 {
		return "", fmt.Errorf("suggest_threshold must be between 0 and 1")
	}

	includeQueue := true
	if req.IncludeQueue != nil {
		includeQueue = *req.IncludeQueue
	}
	queueLimit := clampInt(req.QueueLimit, 25, 1, 200)
	suggestThreshold := req.SuggestThreshold
	if suggestThreshold == 0 {
		suggestThreshold = 0.55
	}

	report := graph.BuildIdentityCalibrationReport(g, graph.IdentityCalibrationOptions{
		SuggestThreshold: suggestThreshold,
		QueueLimit:       queueLimit,
		IncludeQueue:     includeQueue,
	})
	return marshalToolResponse(report)
}

func (a *App) toolCerebroActuateRecommendation(_ context.Context, args json.RawMessage) (string, error) {
	g, err := a.requireSecurityGraph()
	if err != nil {
		return "", err
	}

	var req struct {
		ID               string         `json:"id"`
		RecommendationID string         `json:"recommendation_id"`
		InsightType      string         `json:"insight_type"`
		Title            string         `json:"title"`
		Summary          string         `json:"summary"`
		DecisionID       string         `json:"decision_id"`
		TargetIDs        []string       `json:"target_ids"`
		SourceSystem     string         `json:"source_system"`
		SourceEventID    string         `json:"source_event_id"`
		ObservedAt       time.Time      `json:"observed_at"`
		ValidFrom        time.Time      `json:"valid_from"`
		ValidTo          *time.Time     `json:"valid_to"`
		Confidence       float64        `json:"confidence"`
		AutoGenerated    bool           `json:"auto_generated"`
		Metadata         map[string]any `json:"metadata"`
	}
	if err := decodeToolArgs(args, &req); err != nil {
		return "", err
	}

	result, err := graph.ActuateRecommendation(g, graph.RecommendationActuationRequest{
		ID:               strings.TrimSpace(req.ID),
		RecommendationID: strings.TrimSpace(req.RecommendationID),
		InsightType:      strings.TrimSpace(req.InsightType),
		Title:            strings.TrimSpace(req.Title),
		Summary:          strings.TrimSpace(req.Summary),
		DecisionID:       strings.TrimSpace(req.DecisionID),
		TargetIDs:        req.TargetIDs,
		SourceSystem:     strings.TrimSpace(req.SourceSystem),
		SourceEventID:    strings.TrimSpace(req.SourceEventID),
		ObservedAt:       req.ObservedAt,
		ValidFrom:        req.ValidFrom,
		ValidTo:          req.ValidTo,
		Confidence:       req.Confidence,
		AutoGenerated:    req.AutoGenerated,
		Metadata:         req.Metadata,
	})
	if err != nil {
		return "", err
	}
	return marshalToolResponse(result)
}

func normalizeToolGraphWriteMetadata(observedAt, validFrom time.Time, validTo *time.Time, sourceSystem, sourceEventID string, confidence float64) (time.Time, time.Time, *time.Time, string, string, float64) {
	if observedAt.IsZero() {
		observedAt = time.Now().UTC()
	}
	observedAt = observedAt.UTC()
	if validFrom.IsZero() {
		validFrom = observedAt
	}
	validFrom = validFrom.UTC()

	var validToOut *time.Time
	if validTo != nil && !validTo.IsZero() {
		copy := validTo.UTC()
		validToOut = &copy
	}

	sourceSystem = strings.ToLower(strings.TrimSpace(sourceSystem))
	if sourceSystem == "" {
		sourceSystem = "agent"
	}
	sourceEventID = strings.TrimSpace(sourceEventID)
	if sourceEventID == "" {
		sourceEventID = fmt.Sprintf("tool:%d", observedAt.UnixNano())
	}
	if confidence <= 0 {
		confidence = 0.80
	}
	if confidence > 1 {
		confidence = 1
	}
	return observedAt, validFrom, validToOut, sourceSystem, sourceEventID, confidence
}

func applyToolGraphWriteMetadata(properties map[string]any, observedAt, validFrom time.Time, validTo *time.Time, sourceSystem, sourceEventID string, confidence float64) {
	if properties == nil {
		return
	}
	properties["source_system"] = sourceSystem
	properties["source_event_id"] = sourceEventID
	properties["observed_at"] = observedAt.Format(time.RFC3339)
	properties["valid_from"] = validFrom.Format(time.RFC3339)
	if validTo != nil {
		properties["valid_to"] = validTo.Format(time.RFC3339)
	}
	properties["confidence"] = confidence
}

func cloneToolJSONMap(value map[string]any) map[string]any {
	if len(value) == 0 {
		return map[string]any{}
	}
	out := make(map[string]any, len(value))
	for key, item := range value {
		out[key] = item
	}
	return out
}

func uniqueToolNormalizedIDs(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		normalized := strings.TrimSpace(value)
		if normalized == "" {
			continue
		}
		if _, ok := seen[normalized]; ok {
			continue
		}
		seen[normalized] = struct{}{}
		out = append(out, normalized)
	}
	return out
}

func normalizeToolStringSlice(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		normalized := strings.TrimSpace(value)
		if normalized == "" {
			continue
		}
		if _, ok := seen[normalized]; ok {
			continue
		}
		seen[normalized] = struct{}{}
		out = append(out, normalized)
	}
	return out
}

func toolAnnotationsFromValue(raw any) []map[string]any {
	switch typed := raw.(type) {
	case []map[string]any:
		return append([]map[string]any(nil), typed...)
	case []any:
		out := make([]map[string]any, 0, len(typed))
		for _, item := range typed {
			m, ok := item.(map[string]any)
			if !ok {
				continue
			}
			out = append(out, m)
		}
		return out
	default:
		return []map[string]any{}
	}
}
