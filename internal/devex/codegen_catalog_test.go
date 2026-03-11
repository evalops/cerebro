package devex

import (
	"path/filepath"
	"runtime"
	"testing"
)

func TestBuiltInCodegenCatalogIsValid(t *testing.T) {
	catalog, err := LoadBuiltInCodegenCatalog()
	if err != nil {
		t.Fatalf("load built-in codegen catalog: %v", err)
	}
	if err := ValidateCodegenCatalogReferences(catalog, filepath.Join(repoRoot(t), "Makefile"), filepath.Join(repoRoot(t), ".github", "workflows", "ci.yml")); err != nil {
		t.Fatalf("validate catalog references: %v", err)
	}
}

func repoRoot(t *testing.T) string {
	t.Helper()
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve caller path")
	}
	return filepath.Join(filepath.Dir(filename), "..", "..")
}
