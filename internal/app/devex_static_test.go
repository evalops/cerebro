package app

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestPreCommitHookRunsFastLintOnStagedGoFiles(t *testing.T) {
	root := repoRoot(t)
	hookPath := filepath.Join(root, ".githooks", "pre-commit")
	content, err := os.ReadFile(hookPath)
	if err != nil {
		t.Fatalf("read pre-commit hook: %v", err)
	}
	text := string(content)

	if !strings.Contains(text, "golangci-lint run --fast-only") {
		t.Fatalf("expected pre-commit hook to run golangci-lint --fast-only")
	}
	if !strings.Contains(text, "git diff --cached --name-only --diff-filter=ACM -- '*.go'") {
		t.Fatalf("expected pre-commit hook to lint staged Go files")
	}
}

func TestGolangCILintConfigEnablesTestLinting(t *testing.T) {
	root := repoRoot(t)
	configPath := filepath.Join(root, ".golangci.yml")
	content, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("read golangci config: %v", err)
	}
	text := string(content)

	if !strings.Contains(text, "tests: true") {
		t.Fatalf("expected golangci config to lint tests")
	}
	if !strings.Contains(text, "path: _test\\.go") {
		t.Fatalf("expected golangci config to define test-file exclusion rules")
	}
	if !strings.Contains(text, "- noctx") {
		t.Fatalf("expected golangci config to exclude noctx on test files")
	}
}

func repoRoot(t *testing.T) string {
	t.Helper()

	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(thisFile), "..", ".."))
}
