package vulndb

import (
	"context"
	"strings"
	"testing"
)

func TestImportEPSSCSVRejectsOversizedInputs(t *testing.T) {
	store, err := NewSQLiteStore(t.TempDir() + "/vulndb.db")
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	defer func() { _ = store.Close() }()
	service := NewService(store)

	previousBytes := maxEPSSImportBytes
	previousRows := maxEPSSImportRows
	maxEPSSImportBytes = 32
	maxEPSSImportRows = 2
	t.Cleanup(func() {
		maxEPSSImportBytes = previousBytes
		maxEPSSImportRows = previousRows
	})

	_, err = service.ImportEPSSCSV(context.Background(), "epss-test", strings.NewReader("cve,epss,percentile\nCVE-2026-0001,0.1,0.2\nCVE-2026-0002,0.2,0.3\n"))
	if err == nil {
		t.Fatal("expected oversized EPSS input to fail")
	}
	if !strings.Contains(err.Error(), "exceeded maximum") {
		t.Fatalf("expected maximum-bound error, got %v", err)
	}
}
