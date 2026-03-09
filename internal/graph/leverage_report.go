package graph

import (
	"math"
	"sort"
	"strings"
	"time"
)

const (
	defaultLeverageRecentWindow = 24 * time.Hour
	defaultLeverageDecisionSLA  = 14 * 24 * time.Hour
)

var leverageExpectedSources = []string{
	"github",
	"slack",
	"jira",
	"ci",
	"calendar",
	"docs",
	"incident",
	"support",
	"sales",
	"crm",
}

// GraphLeverageReportOptions controls leverage report generation.
type GraphLeverageReportOptions struct {
	Now                      time.Time
	FreshnessStaleAfter      time.Duration
	SchemaHistoryLimit       int
	SchemaSinceVersion       int64
	IdentitySuggestThreshold float64
	IdentityQueueLimit       int
	RecentWindow             time.Duration
	DecisionStaleAfter       time.Duration
}

// GraphLeverageSummary contains top-line graph leverage KPIs.
type GraphLeverageSummary struct {
	LeverageScore float64 `json:"leverage_score"`
	Grade         string  `json:"grade"`
	CriticalGaps  int     `json:"critical_gaps"`
	Healthy       bool    `json:"healthy"`
}

// GraphSourceCoverage summarizes ingestion footprint for one source system.
type GraphSourceCoverage struct {
	SourceSystem string `json:"source_system"`
	NodeCount    int    `json:"node_count"`
	EdgeCount    int    `json:"edge_count"`
	Total        int    `json:"total"`
}

// GraphIngestionCoverage summarizes source breadth and gaps.
type GraphIngestionCoverage struct {
	ExpectedSources []string              `json:"expected_sources"`
	ObservedSources int                   `json:"observed_sources"`
	CoveragePercent float64               `json:"coverage_percent"`
	MissingSources  []string              `json:"missing_sources,omitempty"`
	SourceCounts    []GraphSourceCoverage `json:"source_counts,omitempty"`
}

// GraphTemporalLeverage summarizes recency and time-window activity quality.
type GraphTemporalLeverage struct {
	Freshness               FreshnessMetrics `json:"freshness"`
	RecentWindowHours       int              `json:"recent_window_hours"`
	RecentNodes             int              `json:"recent_nodes"`
	RecentEdges             int              `json:"recent_edges"`
	ActivityCoveragePercent float64          `json:"activity_coverage_percent"`
}

// GraphClosedLoopLeverage summarizes decision-to-outcome closure maturity.
type GraphClosedLoopLeverage struct {
	DecisionNodes                int     `json:"decision_nodes"`
	OutcomeNodes                 int     `json:"outcome_nodes"`
	DecisionsWithOutcomes        int     `json:"decisions_with_outcomes"`
	ClosureRatePercent           float64 `json:"closure_rate_percent"`
	StaleDecisionsWithoutOutcome int     `json:"stale_decisions_without_outcome"`
}

// GraphPredictiveReadiness summarizes data readiness for prediction and calibration.
type GraphPredictiveReadiness struct {
	LabeledOutcomes        int     `json:"labeled_outcomes"`
	EvidenceNodes          int     `json:"evidence_nodes"`
	FeatureCoveragePercent float64 `json:"feature_coverage_percent"`
	ReadinessScore         float64 `json:"readiness_score"`
}

// GraphQueryReadiness summarizes analyst query interface readiness.
type GraphQueryReadiness struct {
	TemplateCount   int                  `json:"template_count"`
	TemporalCapable bool                 `json:"temporal_capable"`
	Templates       []GraphQueryTemplate `json:"templates,omitempty"`
}

// GraphActuationReadiness summarizes actionability and write-back maturity.
type GraphActuationReadiness struct {
	ActionNodes              int     `json:"action_nodes"`
	AutomatedActions         int     `json:"automated_actions"`
	ActionsWithTargets       int     `json:"actions_with_targets"`
	ActionsLinkedToDecisions int     `json:"actions_linked_to_decisions"`
	ActuationCoveragePercent float64 `json:"actuation_coverage_percent"`
}

// GraphLeverageRecommendation describes one prioritized leverage improvement.
type GraphLeverageRecommendation struct {
	Priority        string `json:"priority"`
	Category        string `json:"category"`
	Title           string `json:"title"`
	Detail          string `json:"detail"`
	SuggestedAction string `json:"suggested_action,omitempty"`
}

// GraphLeverageReport is a unified report for graph leverage and intelligence depth.
type GraphLeverageReport struct {
	GeneratedAt     time.Time                     `json:"generated_at"`
	Summary         GraphLeverageSummary          `json:"summary"`
	Quality         GraphQualityReport            `json:"quality"`
	Identity        IdentityCalibrationReport     `json:"identity"`
	Ingestion       GraphIngestionCoverage        `json:"ingestion"`
	Temporal        GraphTemporalLeverage         `json:"temporal"`
	ClosedLoop      GraphClosedLoopLeverage       `json:"closed_loop"`
	Predictive      GraphPredictiveReadiness      `json:"predictive"`
	Query           GraphQueryReadiness           `json:"query"`
	Actuation       GraphActuationReadiness       `json:"actuation"`
	Recommendations []GraphLeverageRecommendation `json:"recommendations,omitempty"`
}

// BuildGraphLeverageReport builds one deep operational report for graph leverage.
func BuildGraphLeverageReport(g *Graph, opts GraphLeverageReportOptions) GraphLeverageReport {
	now := opts.Now.UTC()
	if now.IsZero() {
		now = time.Now().UTC()
	}

	report := GraphLeverageReport{GeneratedAt: now}
	if g == nil {
		report.Recommendations = []GraphLeverageRecommendation{{
			Priority:        "high",
			Category:        "graph_unavailable",
			Title:           "Security graph is not initialized",
			Detail:          "Leverage metrics are unavailable because the graph is nil.",
			SuggestedAction: "Initialize and ingest graph data before requesting leverage reports.",
		}}
		report.Summary.CriticalGaps = 1
		report.Summary.Healthy = false
		return report
	}

	staleAfter := opts.FreshnessStaleAfter
	if staleAfter <= 0 {
		staleAfter = defaultFreshnessStaleAfter
	}
	recentWindow := opts.RecentWindow
	if recentWindow <= 0 {
		recentWindow = defaultLeverageRecentWindow
	}
	decisionSLA := opts.DecisionStaleAfter
	if decisionSLA <= 0 {
		decisionSLA = defaultLeverageDecisionSLA
	}

	report.Quality = BuildGraphQualityReport(g, GraphQualityReportOptions{
		Now:                 now,
		FreshnessStaleAfter: staleAfter,
		SchemaHistoryLimit:  opts.SchemaHistoryLimit,
		SchemaSinceVersion:  opts.SchemaSinceVersion,
	})
	report.Identity = BuildIdentityCalibrationReport(g, IdentityCalibrationOptions{
		Now:              now,
		SuggestThreshold: opts.IdentitySuggestThreshold,
		QueueLimit:       opts.IdentityQueueLimit,
		IncludeQueue:     true,
	})
	report.Ingestion = buildGraphIngestionCoverage(g)
	report.Temporal = buildGraphTemporalLeverage(g, now, staleAfter, recentWindow)
	report.ClosedLoop = buildGraphClosedLoopLeverage(g, now, decisionSLA)
	report.Predictive = buildGraphPredictiveReadiness(g)
	report.Query = GraphQueryReadiness{
		TemplateCount:   len(DefaultGraphQueryTemplates()),
		TemporalCapable: true,
		Templates:       DefaultGraphQueryTemplates(),
	}
	report.Actuation = buildGraphActuationReadiness(g)
	report.Recommendations = buildGraphLeverageRecommendations(report)

	identityScore := report.Identity.PrecisionPercent / 100
	if report.Identity.AcceptedDecisions+report.Identity.RejectedDecisions == 0 {
		identityScore = report.Identity.LinkagePercent / 100
	}
	queryScore := 0.0
	if report.Query.TemplateCount > 0 {
		queryScore = math.Min(1, float64(report.Query.TemplateCount)/8)
	}
	report.Summary.LeverageScore = 100 * (0.22*(report.Quality.Summary.MaturityScore/100) +
		0.14*clampUnit(identityScore) +
		0.14*clampUnit(report.Ingestion.CoveragePercent/100) +
		0.14*clampUnit(report.Temporal.Freshness.FreshnessPercent/100) +
		0.12*clampUnit(report.ClosedLoop.ClosureRatePercent/100) +
		0.10*clampUnit(report.Predictive.ReadinessScore/100) +
		0.07*clampUnit(queryScore) +
		0.07*clampUnit(report.Actuation.ActuationCoveragePercent/100))
	report.Summary.LeverageScore = math.Round(report.Summary.LeverageScore*10) / 10
	report.Summary.Grade = graphQualityGrade(report.Summary.LeverageScore)
	report.Summary.CriticalGaps = countLeveragePriority(report.Recommendations, "high")
	report.Summary.Healthy = report.Summary.CriticalGaps == 0 && report.Summary.LeverageScore >= 80
	return report
}

func buildGraphIngestionCoverage(g *Graph) GraphIngestionCoverage {
	coverage := GraphIngestionCoverage{
		ExpectedSources: append([]string(nil), leverageExpectedSources...),
	}
	if g == nil {
		return coverage
	}

	type counts struct {
		nodes int
		edges int
	}
	sourceCounts := make(map[string]*counts)

	for _, node := range g.GetAllNodes() {
		if node == nil {
			continue
		}
		source := strings.ToLower(strings.TrimSpace(identityAnyToString(node.Properties["source_system"])))
		if source == "" {
			source = strings.ToLower(strings.TrimSpace(node.Provider))
		}
		if source == "" {
			continue
		}
		entry := sourceCounts[source]
		if entry == nil {
			entry = &counts{}
			sourceCounts[source] = entry
		}
		entry.nodes++
	}

	for _, edges := range g.GetAllEdges() {
		for _, edge := range edges {
			if edge == nil {
				continue
			}
			source := strings.ToLower(strings.TrimSpace(identityAnyToString(edge.Properties["source_system"])))
			if source == "" {
				continue
			}
			entry := sourceCounts[source]
			if entry == nil {
				entry = &counts{}
				sourceCounts[source] = entry
			}
			entry.edges++
		}
	}

	present := make(map[string]struct{}, len(sourceCounts))
	for source, sourceCount := range sourceCounts {
		total := sourceCount.nodes + sourceCount.edges
		if total <= 0 {
			continue
		}
		present[source] = struct{}{}
		coverage.SourceCounts = append(coverage.SourceCounts, GraphSourceCoverage{
			SourceSystem: source,
			NodeCount:    sourceCount.nodes,
			EdgeCount:    sourceCount.edges,
			Total:        total,
		})
	}
	sort.Slice(coverage.SourceCounts, func(i, j int) bool {
		if coverage.SourceCounts[i].Total == coverage.SourceCounts[j].Total {
			return coverage.SourceCounts[i].SourceSystem < coverage.SourceCounts[j].SourceSystem
		}
		return coverage.SourceCounts[i].Total > coverage.SourceCounts[j].Total
	})

	for _, expected := range coverage.ExpectedSources {
		if _, ok := present[expected]; ok {
			coverage.ObservedSources++
			continue
		}
		coverage.MissingSources = append(coverage.MissingSources, expected)
	}
	if len(coverage.ExpectedSources) > 0 {
		coverage.CoveragePercent = (float64(coverage.ObservedSources) / float64(len(coverage.ExpectedSources))) * 100
	}
	coverage.CoveragePercent = math.Round(coverage.CoveragePercent*10) / 10
	return coverage
}

func buildGraphTemporalLeverage(g *Graph, now time.Time, staleAfter, recentWindow time.Duration) GraphTemporalLeverage {
	leverage := GraphTemporalLeverage{
		RecentWindowHours: int(recentWindow.Hours()),
	}
	if g == nil {
		return leverage
	}
	leverage.Freshness = g.Freshness(now, staleAfter)
	cutoff := now.Add(-recentWindow)
	nodes := g.GetAllNodes()
	for _, node := range nodes {
		if node == nil {
			continue
		}
		if observedAt, ok := graphObservedAt(node); ok && !observedAt.Before(cutoff) {
			leverage.RecentNodes++
		}
	}
	for _, edges := range g.GetAllEdges() {
		for _, edge := range edges {
			if edge == nil {
				continue
			}
			if observedAt, ok := temporalPropertyTime(edge.Properties, "observed_at"); ok && !observedAt.Before(cutoff) {
				leverage.RecentEdges++
			}
		}
	}
	if len(nodes) > 0 {
		leverage.ActivityCoveragePercent = (float64(leverage.RecentNodes) / float64(len(nodes))) * 100
	}
	leverage.ActivityCoveragePercent = math.Round(leverage.ActivityCoveragePercent*10) / 10
	return leverage
}

func buildGraphClosedLoopLeverage(g *Graph, now time.Time, decisionSLA time.Duration) GraphClosedLoopLeverage {
	out := GraphClosedLoopLeverage{}
	if g == nil {
		return out
	}
	decisionNodes := g.GetNodesByKind(NodeKindDecision)
	out.DecisionNodes = len(decisionNodes)
	out.OutcomeNodes = len(g.GetNodesByKind(NodeKindOutcome))

	decisionsWithOutcomes := make(map[string]struct{})
	for _, outcome := range g.GetNodesByKind(NodeKindOutcome) {
		if outcome == nil {
			continue
		}
		for _, edge := range g.GetOutEdges(outcome.ID) {
			if edge == nil || edge.Kind != EdgeKindEvaluates {
				continue
			}
			if target, ok := g.GetNode(edge.Target); ok && target != nil && target.Kind == NodeKindDecision {
				decisionsWithOutcomes[target.ID] = struct{}{}
			}
		}
	}
	out.DecisionsWithOutcomes = len(decisionsWithOutcomes)
	if out.DecisionNodes > 0 {
		out.ClosureRatePercent = (float64(out.DecisionsWithOutcomes) / float64(out.DecisionNodes)) * 100
	} else {
		out.ClosureRatePercent = 100
	}
	out.ClosureRatePercent = math.Round(out.ClosureRatePercent*10) / 10

	staleCutoff := now.Add(-decisionSLA)
	for _, decision := range decisionNodes {
		if decision == nil {
			continue
		}
		if _, ok := decisionsWithOutcomes[decision.ID]; ok {
			continue
		}
		observedAt, ok := graphObservedAt(decision)
		if !ok {
			if ts, ok := temporalPropertyTime(decision.Properties, "valid_from"); ok {
				observedAt = ts
			} else {
				observedAt = decision.CreatedAt
			}
		}
		if observedAt.IsZero() || !observedAt.Before(staleCutoff) {
			continue
		}
		out.StaleDecisionsWithoutOutcome++
	}
	return out
}

func buildGraphPredictiveReadiness(g *Graph) GraphPredictiveReadiness {
	out := GraphPredictiveReadiness{}
	if g == nil {
		return out
	}
	out.EvidenceNodes = len(g.GetNodesByKind(NodeKindEvidence))
	for _, outcome := range g.GetNodesByKind(NodeKindOutcome) {
		if outcome == nil {
			continue
		}
		if strings.TrimSpace(identityAnyToString(outcome.Properties["verdict"])) != "" {
			out.LabeledOutcomes++
		}
	}

	nodes := g.GetAllNodes()
	featureReady := 0
	for _, node := range nodes {
		if node == nil {
			continue
		}
		hasObserved := false
		if _, ok := graphObservedAt(node); ok {
			hasObserved = true
		}
		hasSource := strings.TrimSpace(identityAnyToString(node.Properties["source_system"])) != "" || strings.TrimSpace(node.Provider) != ""
		if hasObserved && hasSource {
			featureReady++
		}
	}
	if len(nodes) > 0 {
		out.FeatureCoveragePercent = (float64(featureReady) / float64(len(nodes))) * 100
	}

	labeledScore := math.Min(1, float64(out.LabeledOutcomes)/50)
	evidenceScore := math.Min(1, float64(out.EvidenceNodes)/200)
	featureScore := clampUnit(out.FeatureCoveragePercent / 100)
	out.ReadinessScore = 100 * (0.45*labeledScore + 0.25*evidenceScore + 0.30*featureScore)
	out.FeatureCoveragePercent = math.Round(out.FeatureCoveragePercent*10) / 10
	out.ReadinessScore = math.Round(out.ReadinessScore*10) / 10
	return out
}

func buildGraphActuationReadiness(g *Graph) GraphActuationReadiness {
	out := GraphActuationReadiness{}
	if g == nil {
		return out
	}
	actions := g.GetNodesByKind(NodeKindAction)
	out.ActionNodes = len(actions)
	for _, action := range actions {
		if action == nil {
			continue
		}
		if auto, ok := action.Properties["auto_generated"].(bool); ok && auto {
			out.AutomatedActions++
		}
		hasTarget := false
		for _, edge := range g.GetOutEdges(action.ID) {
			if edge != nil && edge.Kind == EdgeKindTargets {
				hasTarget = true
				break
			}
		}
		if hasTarget {
			out.ActionsWithTargets++
		}
		hasDecision := false
		for _, edge := range g.GetInEdges(action.ID) {
			if edge != nil && edge.Kind == EdgeKindExecutedBy {
				hasDecision = true
				break
			}
		}
		if hasDecision {
			out.ActionsLinkedToDecisions++
		}
	}

	decisions := g.GetNodesByKind(NodeKindDecision)
	if len(decisions) > 0 {
		decisionWithActions := make(map[string]struct{})
		for _, decision := range decisions {
			if decision == nil {
				continue
			}
			for _, edge := range g.GetOutEdges(decision.ID) {
				if edge == nil || edge.Kind != EdgeKindExecutedBy {
					continue
				}
				decisionWithActions[decision.ID] = struct{}{}
			}
		}
		out.ActuationCoveragePercent = (float64(len(decisionWithActions)) / float64(len(decisions))) * 100
	} else {
		out.ActuationCoveragePercent = 100
	}
	out.ActuationCoveragePercent = math.Round(out.ActuationCoveragePercent*10) / 10
	return out
}

func buildGraphLeverageRecommendations(report GraphLeverageReport) []GraphLeverageRecommendation {
	recommendations := make([]GraphLeverageRecommendation, 0, 8)
	add := func(priority, category, title, detail, action string) {
		recommendations = append(recommendations, GraphLeverageRecommendation{
			Priority:        priority,
			Category:        category,
			Title:           title,
			Detail:          detail,
			SuggestedAction: strings.TrimSpace(action),
		})
	}

	if report.Identity.BacklogAliases > 0 && report.Identity.ReviewCoveragePercent < 70 {
		priority := "medium"
		if report.Identity.BacklogAliases > 25 {
			priority = "high"
		}
		add(priority, "identity_review", "Drain identity review backlog", "Alias backlog is limiting canonical identity trust and downstream recommendations.", "Prioritize reviewer queue triage and record accepted/rejected outcomes continuously.")
	}
	if report.Ingestion.CoveragePercent < 70 {
		add("high", "ingestion_breadth", "Expand event ingestion breadth", "Critical source coverage is below target, leaving significant context off-graph.", "Add declarative mappings for missing systems and enforce source onboarding SLOs.")
	}
	if report.Temporal.Freshness.FreshnessPercent < 80 {
		add("medium", "temporal_freshness", "Improve real-time graph freshness", "Stale graph data will degrade insight confidence and incident-time accuracy.", "Reduce sync lag for high-churn domains and enforce observed_at on all writes.")
	}
	if report.ClosedLoop.StaleDecisionsWithoutOutcome > 0 {
		add("medium", "closed_loop", "Close stale decisions with outcomes", "Decisions without outcomes prevent calibration and impact measurement.", "Backfill outcome nodes for stale decisions and enforce outcome write-back in workflows.")
	}
	if report.Predictive.ReadinessScore < 50 {
		add("medium", "predictive_readiness", "Increase labeled outcome volume", "Predictive readiness is low due sparse labels or weak feature completeness.", "Capture more verdict-bearing outcomes and ensure source + temporal metadata completeness.")
	}
	if report.Actuation.ActuationCoveragePercent < 50 {
		add("medium", "actuation", "Increase recommendation actuation coverage", "Too few decisions are linked to executable actions.", "Create action nodes for accepted recommendations and track execution state.")
	}
	if len(recommendations) == 0 {
		add("low", "steady_state", "Maintain leverage baseline", "Identity, ingestion, temporal, and closed-loop leverage metrics are healthy.", "Continue enforcing quality and leverage guardrails in CI and write-back flows.")
	}

	sort.SliceStable(recommendations, func(i, j int) bool {
		if recommendations[i].Priority == recommendations[j].Priority {
			if recommendations[i].Category == recommendations[j].Category {
				return recommendations[i].Title < recommendations[j].Title
			}
			return recommendations[i].Category < recommendations[j].Category
		}
		return graphQualityPriorityRank(recommendations[i].Priority) < graphQualityPriorityRank(recommendations[j].Priority)
	})
	return recommendations
}

func countLeveragePriority(recommendations []GraphLeverageRecommendation, priority string) int {
	priority = strings.ToLower(strings.TrimSpace(priority))
	count := 0
	for _, recommendation := range recommendations {
		if strings.ToLower(strings.TrimSpace(recommendation.Priority)) == priority {
			count++
		}
	}
	return count
}
