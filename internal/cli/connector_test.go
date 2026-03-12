package cli

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type connectorTestState struct {
	output                string
	outputDir             string
	dryRun                bool
	awsPrincipalARN       string
	awsExternalID         string
	awsRoleName           string
	awsTagKey             string
	awsTagValue           string
	gcpProjectID          string
	azureSubscriptionID   string
	syncAzureSubscription string
	runAWS                func(context.Context) (connectorValidationReport, error)
	runGCP                func(context.Context) (connectorValidationReport, error)
	runAzure              func(context.Context) (connectorValidationReport, error)
}

func snapshotConnectorTestState() connectorTestState {
	return connectorTestState{
		output:                connectorOutput,
		outputDir:             connectorScaffoldOutputDir,
		dryRun:                connectorValidateDryRun,
		awsPrincipalARN:       connectorAWSPrincipalARN,
		awsExternalID:         connectorAWSExternalID,
		awsRoleName:           connectorAWSRoleName,
		awsTagKey:             connectorAWSTagKey,
		awsTagValue:           connectorAWSTagValue,
		gcpProjectID:          connectorGCPProjectID,
		azureSubscriptionID:   connectorAzureSubscriptionID,
		syncAzureSubscription: syncAzureSubscription,
		runAWS:                runAWSConnectorValidateFn,
		runGCP:                runGCPConnectorValidateFn,
		runAzure:              runAzureConnectorValidateFn,
	}
}

func restoreConnectorTestState(state connectorTestState) {
	connectorOutput = state.output
	connectorScaffoldOutputDir = state.outputDir
	connectorValidateDryRun = state.dryRun
	connectorAWSPrincipalARN = state.awsPrincipalARN
	connectorAWSExternalID = state.awsExternalID
	connectorAWSRoleName = state.awsRoleName
	connectorAWSTagKey = state.awsTagKey
	connectorAWSTagValue = state.awsTagValue
	connectorGCPProjectID = state.gcpProjectID
	connectorAzureSubscriptionID = state.azureSubscriptionID
	syncAzureSubscription = state.syncAzureSubscription
	runAWSConnectorValidateFn = state.runAWS
	runGCPConnectorValidateFn = state.runGCP
	runAzureConnectorValidateFn = state.runAzure
}

func TestRunConnectorScaffoldWritesAWSBundle(t *testing.T) {
	state := snapshotConnectorTestState()
	defer restoreConnectorTestState(state)

	connectorOutput = FormatTable
	connectorScaffoldOutputDir = t.TempDir()
	connectorAWSRoleName = "CerebroScanRole"
	connectorAWSPrincipalARN = "arn:aws:iam::111122223333:role/Cerebro"
	connectorAWSExternalID = "ext-123"
	connectorAWSTagKey = "CerebroManagedBy"
	connectorAWSTagValue = "cerebro"

	if err := runConnectorScaffold(nil, []string{"aws"}); err != nil {
		t.Fatalf("runConnectorScaffold: %v", err)
	}
	for _, rel := range []string{"aws/stackset.yaml", "aws/parameters.example.json", "aws/README.md"} {
		if _, err := os.Stat(filepath.Join(connectorScaffoldOutputDir, filepath.FromSlash(rel))); err != nil {
			t.Fatalf("expected generated file %s: %v", rel, err)
		}
	}
}

func TestRunConnectorValidateDispatchesAWS(t *testing.T) {
	state := snapshotConnectorTestState()
	defer restoreConnectorTestState(state)

	called := false
	connectorOutput = FormatTable
	runAWSConnectorValidateFn = func(context.Context) (connectorValidationReport, error) {
		called = true
		return connectorValidationReport{
			Provider:    "aws",
			StartedAt:   time.Now().UTC(),
			CompletedAt: time.Now().UTC(),
			Duration:    "1ms",
			Success:     true,
			Checks:      []connectorValidationCheck{{ID: "auth", Status: "passed", Detail: "ok"}},
		}, nil
	}

	cmd := connectorValidateCmd
	cmd.SetContext(context.Background())
	if err := runConnectorValidate(cmd, []string{"aws"}); err != nil {
		t.Fatalf("runConnectorValidate: %v", err)
	}
	if !called {
		t.Fatal("expected AWS validation function to be called")
	}
}

func TestAzureActionMatchesWildcard(t *testing.T) {
	if !azureActionMatches("Microsoft.Compute/*/read", "Microsoft.Compute/virtualMachines/read") {
		t.Fatal("expected wildcard Azure action match")
	}
	if !azureActionMatches("*/read", "Microsoft.Compute/virtualMachines/read") {
		t.Fatal("expected global read Azure wildcard match")
	}
	if azureActionMatches("Microsoft.Compute/snapshots/delete", "Microsoft.Compute/snapshots/write") {
		t.Fatal("expected different Azure actions not to match")
	}
}

func TestAzurePermissionAllowedRespectsAdditiveGrants(t *testing.T) {
	grants := []struct {
		Actions    []string `json:"actions"`
		NotActions []string `json:"notActions"`
	}{
		{
			Actions:    []string{"Microsoft.Compute/*"},
			NotActions: []string{"Microsoft.Compute/snapshots/write"},
		},
		{
			Actions: []string{"Microsoft.Compute/snapshots/write"},
		},
	}
	if !azurePermissionAllowed("Microsoft.Compute/snapshots/write", grants) {
		t.Fatal("expected later additive Azure grant to restore snapshot write permission")
	}
}

func TestClassifyAWSDryRunResult(t *testing.T) {
	status, detail := classifyAWSDryRunResult(nil, "ec2:CreateSnapshot")
	if status != "passed" || !strings.Contains(detail, "succeeded") {
		t.Fatalf("unexpected nil dry-run result: %s %s", status, detail)
	}
	status, _ = classifyAWSDryRunResult(staticConnectorErr("DryRunOperation"), "ec2:CreateSnapshot")
	if status != "passed" {
		t.Fatalf("expected DryRunOperation to pass, got %s", status)
	}
	status, _ = classifyAWSDryRunResult(staticConnectorErr("UnauthorizedOperation"), "ec2:CreateSnapshot")
	if status != "failed" {
		t.Fatalf("expected UnauthorizedOperation to fail, got %s", status)
	}
}

type staticErr string

func (e staticErr) Error() string { return string(e) }

func staticConnectorErr(msg string) error { return staticErr(msg) }
