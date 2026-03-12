package connectors

import (
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
