package app

import (
	"io"
	"log/slog"
	"reflect"
	"testing"

	"github.com/evalops/cerebro/internal/warehouse"
)

func TestInitFindings_FallsBackToConfiguredWarehouseMetadata(t *testing.T) {
	a := &App{
		Config: &Config{
			SnowflakeDatabase: "RAW",
			SnowflakeSchema:   "PUBLIC",
		},
		Logger:    slog.New(slog.NewTextHandler(io.Discard, nil)),
		Warehouse: &warehouse.MemoryWarehouse{},
	}

	a.initFindings()

	if a.SnowflakeFindings == nil {
		t.Fatal("expected snowflake findings store to be initialized")
	}

	schema := reflect.ValueOf(a.SnowflakeFindings).Elem().FieldByName("schema").String()
	if schema != "RAW.PUBLIC" {
		t.Fatalf("expected schema RAW.PUBLIC, got %q", schema)
	}
}
