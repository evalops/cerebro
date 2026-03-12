package connectors

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestRenderAWSBundleDefaults(t *testing.T) {
	bundle, err := RenderAWSBundle(AWSRenderOptions{})
	if err != nil {
		t.Fatalf("RenderAWSBundle: %v", err)
	}
	if bundle.Provider != ProviderAWS {
		t.Fatalf("expected provider %q, got %q", ProviderAWS, bundle.Provider)
	}
	if len(bundle.Files) != 3 {
		t.Fatalf("expected 3 files, got %d", len(bundle.Files))
	}
	if bundle.Files[0].Path != "aws/stackset.yaml" {
		t.Fatalf("expected first file path aws/stackset.yaml, got %q", bundle.Files[0].Path)
	}
	if !strings.Contains(bundle.Files[0].Content, "CerebroScanRole") {
		t.Fatalf("expected stackset to include CerebroScanRole")
	}
}

func TestProviderByIDFindsBuiltIns(t *testing.T) {
	provider, ok := ProviderByID("aws")
	if !ok {
		t.Fatal("expected aws provider catalog to be registered")
	}
	if provider.ID != ProviderAWS {
		t.Fatalf("expected provider ID %q, got %q", ProviderAWS, provider.ID)
	}
}

func TestRenderGCPBundleIncludesWIFResources(t *testing.T) {
	bundle, err := RenderGCPBundle(GCPRenderOptions{EnableWIF: true})
	if err != nil {
		t.Fatalf("RenderGCPBundle: %v", err)
	}
	if len(bundle.Files) != 4 {
		t.Fatalf("expected 4 files, got %d", len(bundle.Files))
	}
	if !strings.Contains(bundle.Files[0].Content, "google_iam_workload_identity_pool") {
		t.Fatalf("expected main.tf to include workload identity pool resource")
	}
}

func TestRenderAzureBundleIncludesARMAndTerraform(t *testing.T) {
	bundle, err := RenderAzureBundle(AzureRenderOptions{})
	if err != nil {
		t.Fatalf("RenderAzureBundle: %v", err)
	}
	if len(bundle.Files) != 6 {
		t.Fatalf("expected 6 files, got %d", len(bundle.Files))
	}
	paths := map[string]bool{}
	for _, file := range bundle.Files {
		paths[file.Path] = true
	}
	for _, required := range []string{"azure/arm-template.json", "azure/main.tf", "azure/README.md"} {
		if !paths[required] {
			t.Fatalf("expected generated file %q", required)
		}
	}
}

func TestRenderAWSBundleEscapesJSONValues(t *testing.T) {
	opts := AWSRenderOptions{
		PrincipalARN: `arn:aws:iam::111122223333:role/Cerebro"Ops`,
		ExternalID:   "ext\\line\nbreak",
		RoleName:     "role\tname",
	}
	bundle, err := RenderAWSBundle(opts)
	if err != nil {
		t.Fatalf("RenderAWSBundle: %v", err)
	}
	var params []map[string]string
	if err := json.Unmarshal([]byte(bundle.Files[1].Content), &params); err != nil {
		t.Fatalf("expected valid AWS parameters JSON: %v\n%s", err, bundle.Files[1].Content)
	}
	if got := params[0]["ParameterValue"]; got != opts.PrincipalARN {
		t.Fatalf("expected principal ARN %q, got %q", opts.PrincipalARN, got)
	}
	if got := params[1]["ParameterValue"]; got != opts.ExternalID {
		t.Fatalf("expected external ID %q, got %q", opts.ExternalID, got)
	}
	if got := params[2]["ParameterValue"]; got != opts.RoleName {
		t.Fatalf("expected role name %q, got %q", opts.RoleName, got)
	}
}

func TestRenderAzureBundleEscapesJSONValues(t *testing.T) {
	opts := AzureRenderOptions{
		SubscriptionID: "sub\\id",
		CustomRoleName: "Cerebro \"Snapshot\"\nOperator",
	}
	bundle, err := RenderAzureBundle(opts)
	if err != nil {
		t.Fatalf("RenderAzureBundle: %v", err)
	}
	var arm map[string]any
	if err := json.Unmarshal([]byte(bundle.Files[0].Content), &arm); err != nil {
		t.Fatalf("expected valid ARM JSON: %v\n%s", err, bundle.Files[0].Content)
	}
	parameters, ok := arm["parameters"].(map[string]any)
	if !ok {
		t.Fatalf("expected ARM parameters map, got %T", arm["parameters"])
	}
	role, ok := parameters["roleName"].(map[string]any)
	if !ok || role["defaultValue"] != opts.CustomRoleName {
		t.Fatalf("expected escaped roleName defaultValue %q, got %#v", opts.CustomRoleName, parameters["roleName"])
	}
	var params map[string]any
	if err := json.Unmarshal([]byte(bundle.Files[1].Content), &params); err != nil {
		t.Fatalf("expected valid ARM parameters JSON: %v\n%s", err, bundle.Files[1].Content)
	}
	paramValues := params["parameters"].(map[string]any)
	subscription := paramValues["subscriptionId"].(map[string]any)
	if subscription["value"] != opts.SubscriptionID {
		t.Fatalf("expected subscription value %q, got %#v", opts.SubscriptionID, subscription["value"])
	}
}
