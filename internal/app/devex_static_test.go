package app

import (
	"os"
	"os/exec"
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

func TestGoVersionScriptMatchesGoMod(t *testing.T) {
	root := repoRoot(t)
	expected := expectedGoVersionFromGoMod(t, root)

	scriptPath := filepath.Join(root, "scripts", "go_version.sh")
	cmd := exec.Command(scriptPath)
	cmd.Dir = root
	output, err := cmd.Output()
	if err != nil {
		t.Fatalf("run go_version.sh: %v", err)
	}
	actual := strings.TrimSpace(string(output))
	if actual != expected {
		t.Fatalf("expected go_version.sh to return %q, got %q", expected, actual)
	}
}

func TestDockerfileUsesGoVersionBuildArg(t *testing.T) {
	root := repoRoot(t)
	dockerfilePath := filepath.Join(root, "Dockerfile")
	content, err := os.ReadFile(dockerfilePath)
	if err != nil {
		t.Fatalf("read Dockerfile: %v", err)
	}
	text := string(content)

	if !strings.Contains(text, "ARG GO_VERSION") {
		t.Fatalf("expected Dockerfile to declare GO_VERSION build arg")
	}
	if !strings.Contains(text, "golang:${GO_VERSION}-alpine") {
		t.Fatalf("expected Dockerfile builder image to use GO_VERSION build arg")
	}
}

func TestWorkflowsUseGoVersionFileFromGoMod(t *testing.T) {
	root := repoRoot(t)
	workflowFiles := []string{
		".github/workflows/ci.yml",
		".github/workflows/release.yml",
		".github/workflows/security-source-scan.yml",
	}

	for _, rel := range workflowFiles {
		abs := filepath.Join(root, rel)
		content, err := os.ReadFile(abs)
		if err != nil {
			t.Fatalf("read workflow %s: %v", rel, err)
		}
		text := string(content)

		if !strings.Contains(text, "go-version-file: go.mod") {
			t.Fatalf("expected workflow %s to use go-version-file: go.mod", rel)
		}
		if strings.Contains(text, "go-version: '1.26.1'") {
			t.Fatalf("expected workflow %s to avoid hardcoded Go version", rel)
		}
	}
}

func TestDockerBuildCommandsPassGoVersionBuildArg(t *testing.T) {
	root := repoRoot(t)

	makefilePath := filepath.Join(root, "Makefile")
	makefileContent, err := os.ReadFile(makefilePath)
	if err != nil {
		t.Fatalf("read Makefile: %v", err)
	}
	makefileText := string(makefileContent)
	if !strings.Contains(makefileText, "GO_VERSION ?= $(shell ./scripts/go_version.sh)") {
		t.Fatalf("expected Makefile to derive GO_VERSION from scripts/go_version.sh")
	}
	if !strings.Contains(makefileText, "docker build --build-arg GO_VERSION=$(GO_VERSION) -t cerebro:latest .") {
		t.Fatalf("expected Makefile docker-build target to pass GO_VERSION build arg")
	}
	if !strings.Contains(makefileText, "docker build --build-arg GO_VERSION=$(GO_VERSION) -f Dockerfile -t $(SECURITY_SCAN_IMAGE) .") {
		t.Fatalf("expected Makefile security scan image build to pass GO_VERSION build arg")
	}

	ciPath := filepath.Join(root, ".github", "workflows", "ci.yml")
	ciContent, err := os.ReadFile(ciPath)
	if err != nil {
		t.Fatalf("read ci workflow: %v", err)
	}
	ciText := string(ciContent)
	if !strings.Contains(ciText, "GO_VERSION=\"$(./scripts/go_version.sh)\"") {
		t.Fatalf("expected CI workflow to derive GO_VERSION from go.mod via script")
	}
	if !strings.Contains(ciText, "docker build --build-arg GO_VERSION=\"${GO_VERSION}\" -f Dockerfile -t cerebro:ci .") {
		t.Fatalf("expected CI workflow Docker build to pass GO_VERSION build arg")
	}
}

func expectedGoVersionFromGoMod(t *testing.T, root string) string {
	t.Helper()

	goModPath := filepath.Join(root, "go.mod")
	content, err := os.ReadFile(goModPath)
	if err != nil {
		t.Fatalf("read go.mod: %v", err)
	}

	fallback := ""
	for _, raw := range strings.Split(string(content), "\n") {
		line := strings.TrimSpace(raw)
		if strings.HasPrefix(line, "toolchain go") {
			return strings.TrimPrefix(line, "toolchain go")
		}
		if strings.HasPrefix(line, "go ") {
			fallback = strings.TrimSpace(strings.TrimPrefix(line, "go "))
		}
	}
	if fallback == "" {
		t.Fatal("go.mod missing both toolchain and go directives")
	}
	return fallback
}

func repoRoot(t *testing.T) string {
	t.Helper()

	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(thisFile), "..", ".."))
}
