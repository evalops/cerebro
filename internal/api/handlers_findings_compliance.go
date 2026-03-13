package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/evalops/cerebro/internal/compliance"
	"github.com/evalops/cerebro/internal/findings"
	"github.com/evalops/cerebro/internal/metrics"
	"github.com/evalops/cerebro/internal/snowflake"
)

var errScanFindingsMissingTables = errors.New("scan request missing tables")

type scanFindingsRequest struct {
	Table  string   `json:"table"`
	Tables []string `json:"tables"`
	Limit  int      `json:"limit"`
}

type scanFindingsTableResult struct {
	Table      string `json:"table"`
	Scanned    int64  `json:"scanned"`
	Violations int64  `json:"violations"`
	Duration   string `json:"duration"`
}

func (s *Server) listFindings(w http.ResponseWriter, r *http.Request) {
	store := s.findingsStoreForRequest(r.Context())
	pagination := ParsePagination(r, 100, 1000)

	filter := findings.FindingFilter{
		Severity:   r.URL.Query().Get("severity"),
		Status:     r.URL.Query().Get("status"),
		PolicyID:   r.URL.Query().Get("policy_id"),
		SignalType: r.URL.Query().Get("signal_type"),
		Domain:     r.URL.Query().Get("domain"),
		Limit:      pagination.Limit,
		Offset:     pagination.Offset,
	}

	total := store.Count(filter)
	list := store.List(filter)
	paginationResp := BuildPaginationResponse(int64(total), pagination, len(list))

	s.json(w, http.StatusOK, map[string]interface{}{
		"findings":   list,
		"count":      len(list),
		"pagination": paginationResp,
	})
}

func (s *Server) findingsStats(w http.ResponseWriter, r *http.Request) {
	store := s.findingsStoreForRequest(r.Context())
	stats := store.Stats()
	s.json(w, http.StatusOK, stats)
}

func (s *Server) signalsDashboard(w http.ResponseWriter, r *http.Request) {
	store := s.findingsStoreForRequest(r.Context())
	stats := store.Stats()
	open := store.Count(findings.FindingFilter{Status: "OPEN"})
	snoozed := store.Count(findings.FindingFilter{Status: "SNOOZED"})
	recent := store.List(findings.FindingFilter{Limit: 25})

	s.json(w, http.StatusOK, map[string]interface{}{
		"summary": map[string]interface{}{
			"total_signals":   stats.Total,
			"open_signals":    open,
			"snoozed_signals": snoozed,
		},
		"stats":          stats,
		"recent_signals": recent,
		"count":          len(recent),
	})
}

func (s *Server) getFinding(w http.ResponseWriter, r *http.Request) {
	store := s.findingsStoreForRequest(r.Context())
	id := chi.URLParam(r, "id")
	f, ok := store.Get(id)
	if !ok {
		s.error(w, http.StatusNotFound, "finding not found")
		return
	}
	s.json(w, http.StatusOK, f)
}

func (s *Server) deleteFinding(w http.ResponseWriter, r *http.Request) {
	store := s.findingsStoreForRequest(r.Context())
	id := chi.URLParam(r, "id")
	if strings.TrimSpace(id) == "" {
		s.error(w, http.StatusBadRequest, "finding id required")
		return
	}

	now := time.Now().UTC()
	err := store.Update(id, func(f *findings.Finding) error {
		f.Status = "DELETED"
		f.ResourceStatus = "Deleted"
		f.Resolution = "deleted via api"
		f.UpdatedAt = now
		f.StatusChangedAt = &now
		f.ResolvedAt = &now
		return nil
	})
	if errors.Is(err, findings.ErrIssueNotFound) {
		s.error(w, http.StatusNotFound, "finding not found")
		return
	}
	if err != nil {
		s.errorFromErr(w, err)
		return
	}

	s.json(w, http.StatusOK, map[string]string{
		"status": "deleted",
		"id":     id,
	})
}

func (s *Server) scanFindings(w http.ResponseWriter, r *http.Request) {
	req, tables, err := decodeScanFindingsRequest(r)
	if err != nil {
		if errors.Is(err, errScanFindingsMissingTables) {
			s.error(w, http.StatusBadRequest, "table or tables required")
			return
		}
		s.error(w, http.StatusBadRequest, "invalid request")
		return
	}

	store := s.findingsStoreForRequest(r.Context())
	if s.app.Warehouse == nil {
		s.error(w, http.StatusServiceUnavailable, "snowflake not configured")
		return
	}

	start := time.Now()
	totalScanned := int64(0)
	totalViolations := int64(0)
	allFindings := make([]interface{}, 0)
	tableResults := make([]scanFindingsTableResult, 0, len(tables))

	for _, table := range tables {
		tableStart := time.Now()
		assets, err := s.app.Warehouse.GetAssets(r.Context(), table, snowflake.AssetFilter{Limit: req.Limit})
		if err != nil {
			s.errorFromErr(w, err)
			return
		}

		result := s.app.Scanner.ScanAssets(r.Context(), assets)

		for _, f := range result.Findings {
			store.Upsert(r.Context(), f)
			allFindings = append(allFindings, f)
		}

		totalScanned += result.Scanned
		totalViolations += result.Violations
		tableResults = append(tableResults, scanFindingsTableResult{
			Table:      table,
			Scanned:    result.Scanned,
			Violations: result.Violations,
			Duration:   time.Since(tableStart).String(),
		})
	}

	s.json(w, http.StatusOK, map[string]interface{}{
		"scanned":    totalScanned,
		"violations": totalViolations,
		"duration":   time.Since(start).String(),
		"findings":   allFindings,
		"tables":     tableResults,
	})
}

func decodeScanFindingsRequest(r *http.Request) (scanFindingsRequest, []string, error) {
	var req scanFindingsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		return scanFindingsRequest{}, nil, err
	}

	if req.Limit <= 0 {
		req.Limit = 100
	}

	tables := normalizeScanRequestTables(req.Table, req.Tables)
	if len(tables) == 0 {
		return scanFindingsRequest{}, nil, errScanFindingsMissingTables
	}

	return req, tables, nil
}

func normalizeScanRequestTables(table string, tables []string) []string {
	rawTables := append([]string(nil), tables...)
	if strings.TrimSpace(table) != "" {
		rawTables = append(rawTables, table)
	}

	normalized := make([]string, 0, len(rawTables))
	seen := make(map[string]struct{}, len(rawTables))
	for _, tableName := range rawTables {
		candidate := strings.TrimSpace(strings.ToLower(tableName))
		if candidate == "" {
			continue
		}
		if _, exists := seen[candidate]; exists {
			continue
		}
		seen[candidate] = struct{}{}
		normalized = append(normalized, candidate)
	}

	return normalized
}

func (s *Server) resolveFinding(w http.ResponseWriter, r *http.Request) {
	store := s.findingsStoreForRequest(r.Context())
	id := chi.URLParam(r, "id")
	if store.Resolve(id) {
		s.json(w, http.StatusOK, map[string]string{"status": "resolved"})
	} else {
		s.error(w, http.StatusNotFound, "finding not found")
	}
}

func (s *Server) suppressFinding(w http.ResponseWriter, r *http.Request) {
	store := s.findingsStoreForRequest(r.Context())
	id := chi.URLParam(r, "id")
	if store.Suppress(id) {
		s.json(w, http.StatusOK, map[string]string{"status": "suppressed"})
	} else {
		s.error(w, http.StatusNotFound, "finding not found")
	}
}

func (s *Server) exportFindings(w http.ResponseWriter, r *http.Request) {
	store := s.findingsStoreForRequest(r.Context())
	filter := findings.FindingFilter{
		Severity:   r.URL.Query().Get("severity"),
		Status:     r.URL.Query().Get("status"),
		PolicyID:   r.URL.Query().Get("policy_id"),
		SignalType: r.URL.Query().Get("signal_type"),
		Domain:     r.URL.Query().Get("domain"),
	}
	list := store.List(filter)

	// Enrich findings with cloud URLs, tags, etc.
	for _, f := range list {
		findings.EnrichFinding(f)
	}

	format := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("format")))
	if format == "" {
		format = "csv"
	}

	var data []byte
	var err error
	var contentType string

	switch format {
	case "json":
		exporter := findings.NewJSONExporter(r.URL.Query().Get("pretty") == "true")
		data, err = exporter.Export(list)
		contentType = "application/json"
	case "csv":
		exporter := findings.NewCSVExporter()
		data, err = exporter.Export(list)
		contentType = "text/csv"
	default:
		s.error(w, http.StatusBadRequest, "invalid format, expected csv or json")
		return
	}

	if err != nil {
		s.errorFromErr(w, err)
		return
	}

	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=findings.%s", format))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data) // #nosec G705 -- payload is generated server-side exporter output (CSV/JSON)
}

func (s *Server) assignFinding(w http.ResponseWriter, r *http.Request) {
	store := s.findingsStoreForRequest(r.Context())
	id := chi.URLParam(r, "id")
	var req struct {
		Assignee string `json:"assignee"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.error(w, http.StatusBadRequest, "invalid request")
		return
	}

	mgr := findings.NewIssueManager(store)
	if err := mgr.Assign(id, req.Assignee); err != nil {
		if errors.Is(err, findings.ErrIssueNotFound) {
			s.error(w, http.StatusNotFound, "finding not found")
		} else {
			s.errorFromErr(w, err)
		}
		return
	}
	s.json(w, http.StatusOK, map[string]string{"status": "assigned", "assignee": req.Assignee})
}

func (s *Server) setFindingDueDate(w http.ResponseWriter, r *http.Request) {
	store := s.findingsStoreForRequest(r.Context())
	id := chi.URLParam(r, "id")
	var req struct {
		DueAt time.Time `json:"due_at"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.error(w, http.StatusBadRequest, "invalid request")
		return
	}

	mgr := findings.NewIssueManager(store)
	if err := mgr.SetDueDate(id, req.DueAt); err != nil {
		if errors.Is(err, findings.ErrIssueNotFound) {
			s.error(w, http.StatusNotFound, "finding not found")
		} else {
			s.errorFromErr(w, err)
		}
		return
	}
	s.json(w, http.StatusOK, map[string]string{"status": "updated"})
}

func (s *Server) addFindingNote(w http.ResponseWriter, r *http.Request) {
	store := s.findingsStoreForRequest(r.Context())
	id := chi.URLParam(r, "id")
	var req struct {
		Note string `json:"note"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.error(w, http.StatusBadRequest, "invalid request")
		return
	}

	mgr := findings.NewIssueManager(store)
	if err := mgr.AddNote(id, req.Note); err != nil {
		if errors.Is(err, findings.ErrIssueNotFound) {
			s.error(w, http.StatusNotFound, "finding not found")
		} else {
			s.errorFromErr(w, err)
		}
		return
	}
	s.json(w, http.StatusOK, map[string]string{"status": "note added"})
}

func (s *Server) linkFindingTicket(w http.ResponseWriter, r *http.Request) {
	store := s.findingsStoreForRequest(r.Context())
	id := chi.URLParam(r, "id")
	var req struct {
		URL        string `json:"url"`
		Name       string `json:"name"`
		ExternalID string `json:"external_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.error(w, http.StatusBadRequest, "invalid request")
		return
	}

	mgr := findings.NewIssueManager(store)
	if err := mgr.LinkTicket(id, req.URL, req.Name, req.ExternalID); err != nil {
		if errors.Is(err, findings.ErrIssueNotFound) {
			s.error(w, http.StatusNotFound, "finding not found")
		} else {
			s.errorFromErr(w, err)
		}
		return
	}
	s.json(w, http.StatusOK, map[string]string{"status": "ticket linked"})
}

// Reporting endpoints

func (s *Server) executiveSummary(w http.ResponseWriter, r *http.Request) {
	reporter := findings.NewComplianceReporter(s.findingsStoreForRequest(r.Context()), s.app.Policy)
	summary := reporter.GenerateExecutiveSummary()
	s.json(w, http.StatusOK, summary)
}

func (s *Server) riskSummary(w http.ResponseWriter, r *http.Request) {
	reporter := findings.NewComplianceReporter(s.findingsStoreForRequest(r.Context()), s.app.Policy)
	risks := reporter.GenerateRiskSummary()
	s.json(w, http.StatusOK, map[string]interface{}{"risks": risks, "count": len(risks)})
}

func (s *Server) frameworkComplianceReport(w http.ResponseWriter, r *http.Request) {
	framework := chi.URLParam(r, "framework")
	definition := compliance.GetFramework(framework)
	if definition == nil {
		reporter := findings.NewComplianceReporter(s.findingsStoreForRequest(r.Context()), s.app.Policy)
		report := reporter.GenerateFrameworkReport(framework)
		s.json(w, http.StatusOK, report)
		return
	}

	report := s.evaluateComplianceFramework(r.Context(), definition)
	legacy := map[string]interface{}{
		"framework":             definition.Name,
		"total_controls":        report.Summary.TotalControls,
		"assessed_controls":     report.Summary.TotalControls - report.Summary.NotApplicableControls,
		"passing_controls":      report.Summary.PassingControls,
		"failing_controls":      report.Summary.FailingControls + report.Summary.PartialControls,
		"not_assessed_controls": report.Summary.NotApplicableControls,
		"coverage_percent":      report.Summary.ComplianceScore,
		"compliance_percent":    report.Summary.ComplianceScore,
		"control_status":        make(map[string]map[string]interface{}, len(report.Controls)),
		"findings_by_control":   make(map[string][]string, len(report.Controls)),
	}
	for _, ctrl := range report.Controls {
		status := "NOT_ASSESSED"
		switch ctrl.Status {
		case compliance.ControlStatePassing:
			status = "PASS"
		case compliance.ControlStateFailing, compliance.ControlStatePartial:
			status = "FAIL"
		}
		legacy["control_status"].(map[string]map[string]interface{})[ctrl.ControlID] = map[string]interface{}{
			"control_id":   ctrl.ControlID,
			"control_name": ctrl.Title,
			"status":       status,
			"findings":     ctrl.FailCount,
			"policy_ids":   ctrl.PolicyIDs,
		}
		findingsByControl := make([]string, 0)
		for _, item := range ctrl.Evidence {
			if item.PolicyID != "" && item.Status == compliance.ControlStateFailing {
				findingsByControl = append(findingsByControl, item.PolicyID)
			}
		}
		legacy["findings_by_control"].(map[string][]string)[ctrl.ControlID] = findingsByControl
	}
	s.json(w, http.StatusOK, legacy)
}

// Compliance endpoints

func (s *Server) listFrameworks(w http.ResponseWriter, r *http.Request) {
	frameworks := compliance.GetFrameworks()
	s.json(w, http.StatusOK, map[string]interface{}{"frameworks": frameworks, "count": len(frameworks)})
}

func (s *Server) getFramework(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	f := compliance.GetFramework(id)
	if f == nil {
		s.error(w, http.StatusNotFound, "framework not found")
		return
	}
	s.json(w, http.StatusOK, f)
}

func (s *Server) generateComplianceReport(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	framework := compliance.GetFramework(id)
	if framework == nil {
		s.error(w, http.StatusNotFound, "framework not found")
		return
	}
	report := s.evaluateComplianceFramework(r.Context(), framework)
	totalFindings := 0
	controlEvidence := make(map[string][]compliance.ControlEvidence)
	for _, ctrl := range report.Controls {
		totalFindings += ctrl.FailCount
		if len(ctrl.Evidence) > 0 {
			controlEvidence[ctrl.ControlID] = ctrl.Evidence
		}
	}
	response := map[string]interface{}{
		"report":         report,
		"total_findings": totalFindings,
		"evidence":       controlEvidence,
	}

	s.json(w, http.StatusOK, response)
}

// Pre-audit health check - predicts audit outcome
func (s *Server) preAuditCheck(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	framework := compliance.GetFramework(id)
	if framework == nil {
		s.error(w, http.StatusNotFound, "framework not found")
		return
	}

	type ControlCheck struct {
		ControlID   string   `json:"control_id"`
		Title       string   `json:"title"`
		Status      string   `json:"status"` // passing, failing, at_risk
		Issues      []string `json:"issues,omitempty"`
		Findings    []string `json:"findings,omitempty"`
		Remediation string   `json:"remediation,omitempty"`
	}

	checks := make([]ControlCheck, 0, len(framework.Controls))
	passing, failing, atRisk := 0, 0, 0

	report := s.evaluateComplianceFramework(r.Context(), framework)
	for _, ctrl := range report.Controls {
		check := ControlCheck{
			ControlID: ctrl.ControlID,
			Title:     ctrl.Title,
			Status:    "passing",
		}
		switch ctrl.Status {
		case compliance.ControlStateFailing:
			check.Status = "failing"
		case compliance.ControlStatePartial, compliance.ControlStateUnknown:
			check.Status = "at_risk"
		case compliance.ControlStateNotApplicable:
			check.Status = "passing"
		}
		for _, item := range ctrl.Evidence {
			if item.Status == compliance.ControlStatePassing {
				continue
			}
			if item.Reason != "" {
				check.Issues = append(check.Issues, item.Reason)
			}
			if item.PolicyID != "" {
				check.Findings = append(check.Findings, item.PolicyID)
			}
		}

		switch check.Status {
		case "passing":
			passing++
		case "failing":
			failing++
			check.Remediation = "Review and remediate findings before audit"
		case "at_risk":
			atRisk++
			check.Remediation = "Collect missing evidence or close ambiguous control gaps before audit"
		}

		checks = append(checks, check)
	}

	// Determine estimated outcome
	outcome := "PASS"
	if failing > 0 {
		outcome = fmt.Sprintf("PASS WITH %d EXCEPTIONS", failing)
	}
	if len(framework.Controls) > 0 && float64(failing)/float64(len(framework.Controls)) > 0.2 {
		outcome = "AT RISK - RECOMMEND POSTPONING"
	}

	score := 0.0
	if len(framework.Controls) > 0 {
		score = float64(passing) / float64(len(framework.Controls)) * 100
	}

	s.json(w, http.StatusOK, map[string]interface{}{
		"framework_id":      framework.ID,
		"framework_name":    framework.Name,
		"generated_at":      report.GeneratedAt,
		"estimated_outcome": outcome,
		"summary": map[string]interface{}{
			"total_controls":   report.Summary.TotalControls,
			"passing":          passing,
			"failing":          failing,
			"at_risk":          atRisk,
			"compliance_score": fmt.Sprintf("%.1f%%", score),
		},
		"controls":        checks,
		"recommendations": s.generateAuditRecommendations(failing, atRisk, len(framework.Controls)),
	})
}

func (s *Server) generateAuditRecommendations(failing, atRisk, total int) []string {
	var recs []string

	if failing > 0 {
		recs = append(recs, fmt.Sprintf("Remediate %d failing controls before audit", failing))
	}
	if atRisk > 0 {
		recs = append(recs, fmt.Sprintf("Review %d at-risk controls", atRisk))
	}
	if failing == 0 && atRisk == 0 {
		recs = append(recs, "All controls passing - ready for audit")
	}
	if total > 0 && float64(failing)/float64(total) > 0.1 {
		recs = append(recs, "Consider postponing audit until critical issues are resolved")
	}

	return recs
}

func (s *Server) openFindingsByPolicy(store findings.FindingStore) map[string]int {
	counts := make(map[string]int)
	for _, finding := range store.List(findings.FindingFilter{Status: "OPEN"}) {
		if finding.PolicyID == "" {
			continue
		}
		counts[finding.PolicyID]++
	}
	return counts
}

// Export audit package with evidence
func (s *Server) exportAuditPackage(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	framework := compliance.GetFramework(id)
	if framework == nil {
		metrics.RecordComplianceExport(false)
		s.error(w, http.StatusNotFound, "framework not found")
		return
	}

	generatedAt := time.Now().UTC()
	report := s.evaluateComplianceFramework(r.Context(), framework)
	if report.GeneratedAt == "" {
		report.GeneratedAt = generatedAt.Format(time.RFC3339)
	}
	pkg := compliance.BuildAuditPackageFromReport(framework, report)

	zipBytes, err := compliance.RenderAuditPackageZIP(pkg)
	if err != nil {
		metrics.RecordComplianceExport(false)
		s.error(w, http.StatusInternalServerError, fmt.Sprintf("failed to render audit package: %v", err))
		return
	}

	filename := compliance.AuditPackageFilename(framework.ID, generatedAt)
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", filename))
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write(zipBytes); err != nil { // #nosec G705 -- payload is server-generated ZIP bytes
		metrics.RecordComplianceExport(false)
		s.app.Logger.Warn("failed to stream audit package", "error", err, "framework_id", framework.ID)
		return
	}
	metrics.RecordComplianceExport(true)
}

func (s *Server) evaluateComplianceFramework(ctx context.Context, framework *compliance.Framework) compliance.ComplianceReport {
	return compliance.EvaluateFramework(s.currentTenantSecurityGraph(ctx), framework, compliance.EvaluationOptions{
		GeneratedAt:          time.Now().UTC(),
		OpenFindingsByPolicy: s.openFindingsByPolicy(s.findingsStoreForRequest(ctx)),
	})
}
