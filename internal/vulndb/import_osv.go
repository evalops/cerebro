package vulndb

import (
	"bufio"
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"
)

var (
	maxEPSSImportBytes int64 = 256 << 20
	maxEPSSImportRows        = 1_000_000
)

type osvAdvisory struct {
	ID               string          `json:"id"`
	Aliases          []string        `json:"aliases"`
	Summary          string          `json:"summary"`
	Details          string          `json:"details"`
	Published        time.Time       `json:"published"`
	Modified         time.Time       `json:"modified"`
	Withdrawn        *time.Time      `json:"withdrawn"`
	Severity         []osvSeverity   `json:"severity"`
	References       []osvReference  `json:"references"`
	Affected         []osvAffected   `json:"affected"`
	DatabaseSpecific json.RawMessage `json:"database_specific"`
}

type osvSeverity struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}

type osvReference struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}

type osvAffected struct {
	Package struct {
		Ecosystem string `json:"ecosystem"`
		Name      string `json:"name"`
		PURL      string `json:"purl"`
	} `json:"package"`
	Ranges []struct {
		Type   string `json:"type"`
		Events []struct {
			Introduced   string `json:"introduced"`
			Fixed        string `json:"fixed"`
			LastAffected string `json:"last_affected"`
		} `json:"events"`
	} `json:"ranges"`
	Versions []string `json:"versions"`
}

type ImportReport struct {
	Source      string `json:"source"`
	Imported    int    `json:"imported"`
	MatchedEPSS int64  `json:"matched_epss"`
	MatchedKEV  int64  `json:"matched_kev"`
}

func (s *Service) ImportOSVJSON(ctx context.Context, source string, r io.Reader) (ImportReport, error) {
	if s == nil || s.store == nil {
		return ImportReport{}, fmt.Errorf("vulnerability database service is not configured")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	reader := bufio.NewReader(r)
	first, err := firstNonSpaceByte(reader)
	if err != nil {
		return ImportReport{}, err
	}
	decoder := json.NewDecoder(reader)
	report := ImportReport{Source: strings.TrimSpace(source)}
	importOne := func(doc osvAdvisory) error {
		vuln, affected := normalizeOSVAdvisory(doc)
		if vuln.ID == "" {
			return nil
		}
		if err := s.store.UpsertAdvisory(ctx, vuln, affected); err != nil {
			return err
		}
		report.Imported++
		return nil
	}
	if first == '[' {
		tok, err := decoder.Token()
		if err != nil {
			return report, fmt.Errorf("read osv array start: %w", err)
		}
		if _, ok := tok.(json.Delim); !ok {
			return report, fmt.Errorf("invalid osv array stream")
		}
		for decoder.More() {
			var doc osvAdvisory
			if err := decoder.Decode(&doc); err != nil {
				return report, fmt.Errorf("decode osv advisory: %w", err)
			}
			if err := importOne(doc); err != nil {
				return report, fmt.Errorf("import osv advisory %s: %w", doc.ID, err)
			}
		}
		if _, err := decoder.Token(); err != nil {
			return report, fmt.Errorf("read osv array end: %w", err)
		}
	} else {
		for {
			var doc osvAdvisory
			if err := decoder.Decode(&doc); err != nil {
				if err == io.EOF {
					break
				}
				return report, fmt.Errorf("decode osv advisory stream: %w", err)
			}
			if err := importOne(doc); err != nil {
				return report, fmt.Errorf("import osv advisory %s: %w", doc.ID, err)
			}
		}
	}
	attemptedAt := s.now().UTC()
	if err := s.store.UpdateSyncState(ctx, SyncState{Source: report.Source, LastAttemptAt: attemptedAt, LastSuccessAt: attemptedAt, RecordsSynced: report.Imported}); err != nil {
		return report, err
	}
	return report, nil
}

func (s *Service) ImportKEVJSON(ctx context.Context, source string, r io.Reader) (ImportReport, error) {
	if s == nil || s.store == nil {
		return ImportReport{}, fmt.Errorf("vulnerability database service is not configured")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	var payload struct {
		Vulnerabilities []struct {
			CVEID string `json:"cveID"`
		} `json:"vulnerabilities"`
	}
	if err := json.NewDecoder(r).Decode(&payload); err != nil {
		return ImportReport{}, fmt.Errorf("decode kev feed: %w", err)
	}
	cves := make([]string, 0, len(payload.Vulnerabilities))
	for _, vuln := range payload.Vulnerabilities {
		if strings.TrimSpace(vuln.CVEID) != "" {
			cves = append(cves, vuln.CVEID)
		}
	}
	matched, err := s.store.MarkKEV(ctx, cves)
	if err != nil {
		return ImportReport{}, err
	}
	now := s.now().UTC()
	report := ImportReport{Source: strings.TrimSpace(source), Imported: len(cves), MatchedKEV: matched}
	if err := s.store.UpdateSyncState(ctx, SyncState{Source: report.Source, LastAttemptAt: now, LastSuccessAt: now, RecordsSynced: report.Imported}); err != nil {
		return report, err
	}
	return report, nil
}

func (s *Service) ImportEPSSCSV(ctx context.Context, source string, r io.Reader) (ImportReport, error) {
	if s == nil || s.store == nil {
		return ImportReport{}, fmt.Errorf("vulnerability database service is not configured")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	limited := &io.LimitedReader{R: r, N: maxEPSSImportBytes + 1}
	reader := csv.NewReader(limited)
	reader.FieldsPerRecord = -1
	report := ImportReport{Source: strings.TrimSpace(source)}
	rowCount := 0
	for {
		record, err := reader.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return ImportReport{}, fmt.Errorf("read epss csv: %w", err)
		}
		rowCount++
		if rowCount > maxEPSSImportRows {
			return report, fmt.Errorf("epss csv exceeded maximum row count %d", maxEPSSImportRows)
		}
		if len(record) < 3 {
			continue
		}
		if rowCount == 1 && strings.EqualFold(strings.TrimSpace(record[0]), "cve") {
			continue
		}
		score, err := strconv.ParseFloat(strings.TrimSpace(record[1]), 64)
		if err != nil {
			continue
		}
		percentile, err := strconv.ParseFloat(strings.TrimSpace(record[2]), 64)
		if err != nil {
			continue
		}
		updated, err := s.store.UpsertEPSS(ctx, record[0], score, percentile)
		if err != nil {
			return report, err
		}
		report.Imported++
		report.MatchedEPSS += updated
	}
	if limited.N == 0 {
		return report, fmt.Errorf("epss csv exceeded maximum size %d bytes", maxEPSSImportBytes)
	}
	now := s.now().UTC()
	if err := s.store.UpdateSyncState(ctx, SyncState{Source: report.Source, LastAttemptAt: now, LastSuccessAt: now, RecordsSynced: report.Imported}); err != nil {
		return report, err
	}
	return report, nil
}

func normalizeOSVAdvisory(doc osvAdvisory) (Vulnerability, []AffectedPackage) {
	vuln := Vulnerability{
		ID:          strings.TrimSpace(strings.ToUpper(doc.ID)),
		Aliases:     uniqueUpperStrings(doc.Aliases),
		Summary:     strings.TrimSpace(doc.Summary),
		Details:     strings.TrimSpace(doc.Details),
		PublishedAt: doc.Published,
		ModifiedAt:  doc.Modified,
		WithdrawnAt: doc.Withdrawn,
		Source:      "osv",
	}
	vuln.Severity, vuln.CVSS = extractOSVSeverity(doc)
	for _, ref := range doc.References {
		if strings.TrimSpace(ref.URL) != "" {
			vuln.References = append(vuln.References, strings.TrimSpace(ref.URL))
		}
	}
	affected := make([]AffectedPackage, 0)
	for _, pkg := range doc.Affected {
		ecosystem := normalizeEcosystem(pkg.Package.Ecosystem)
		packageName := strings.TrimSpace(strings.ToLower(pkg.Package.Name))
		if ecosystem == "" || packageName == "" {
			continue
		}
		for _, version := range uniqueStrings(pkg.Versions) {
			affected = append(affected, AffectedPackage{
				VulnerabilityID:   vuln.ID,
				Ecosystem:         ecosystem,
				PackageName:       packageName,
				RangeType:         "EXACT",
				VulnerableVersion: strings.TrimSpace(version),
			})
		}
		for _, item := range pkg.Ranges {
			currentIntroduced := ""
			rangeType := strings.TrimSpace(strings.ToUpper(item.Type))
			for _, event := range item.Events {
				if strings.TrimSpace(event.Introduced) != "" {
					currentIntroduced = strings.TrimSpace(event.Introduced)
					if currentIntroduced == "0" {
						currentIntroduced = ""
					}
				}
				if strings.TrimSpace(event.Fixed) != "" {
					affected = append(affected, AffectedPackage{
						VulnerabilityID: vuln.ID,
						Ecosystem:       ecosystem,
						PackageName:     packageName,
						RangeType:       rangeType,
						Introduced:      currentIntroduced,
						Fixed:           strings.TrimSpace(event.Fixed),
					})
					currentIntroduced = ""
					continue
				}
				if strings.TrimSpace(event.LastAffected) != "" {
					affected = append(affected, AffectedPackage{
						VulnerabilityID: vuln.ID,
						Ecosystem:       ecosystem,
						PackageName:     packageName,
						RangeType:       rangeType,
						Introduced:      currentIntroduced,
						LastAffected:    strings.TrimSpace(event.LastAffected),
					})
					currentIntroduced = ""
				}
			}
			if currentIntroduced != "" {
				affected = append(affected, AffectedPackage{
					VulnerabilityID: vuln.ID,
					Ecosystem:       ecosystem,
					PackageName:     packageName,
					RangeType:       rangeType,
					Introduced:      currentIntroduced,
				})
			}
		}
	}
	return vuln, affected
}

func extractOSVSeverity(doc osvAdvisory) (string, float64) {
	if len(doc.DatabaseSpecific) > 0 {
		var databaseSpecific map[string]any
		if err := json.Unmarshal(doc.DatabaseSpecific, &databaseSpecific); err == nil {
			if raw, ok := databaseSpecific["severity"].(string); ok {
				severity := normalizeSeverity(raw)
				if severity != "" {
					return severity, 0
				}
			}
		}
	}
	for _, sev := range doc.Severity {
		score, err := strconv.ParseFloat(strings.TrimSpace(sev.Score), 64)
		if err == nil {
			return severityFromScore(score), score
		}
	}
	return "unknown", 0
}

func firstNonSpaceByte(r *bufio.Reader) (byte, error) {
	for {
		b, err := r.ReadByte()
		if err != nil {
			if err == io.EOF {
				return 0, fmt.Errorf("empty advisory stream")
			}
			return 0, err
		}
		if !strings.ContainsRune(" \n\r\t", rune(b)) {
			if err := r.UnreadByte(); err != nil {
				return 0, err
			}
			return b, nil
		}
	}
}
