package filesystemanalyzer

import (
	"context"
	"path/filepath"
	"testing"
)

func TestAnalyzerBuildsNPMDependencyGraphAndReachability(t *testing.T) {
	root := t.TempDir()
	mustWriteFile(t, filepath.Join(root, "srv", "app", "package-lock.json"), `{
  "name": "demo",
  "lockfileVersion": 2,
  "packages": {
    "": {
      "name": "demo",
      "version": "1.0.0",
      "dependencies": {
        "express": "4.18.2",
        "lodash": "4.17.21"
      }
    },
    "node_modules/express": {
      "version": "4.18.2",
      "dependencies": {
        "body-parser": "1.20.2"
      }
    },
    "node_modules/body-parser": {
      "version": "1.20.2"
    },
    "node_modules/lodash": {
      "version": "4.17.21"
    }
  }
}`)
	mustWriteFile(t, filepath.Join(root, "srv", "app", "src", "index.js"), "const express = require('express')\napp.use(express.json())\n")

	report, err := New(Options{}).Analyze(context.Background(), root)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}

	pkgs := make(map[string]PackageRecord, len(report.Packages))
	for _, pkg := range report.Packages {
		pkgs[pkg.Ecosystem+"|"+pkg.Name+"|"+pkg.Version] = pkg
	}

	if len(pkgs) != 3 {
		t.Fatalf("expected 3 npm packages from package-lock, got %#v", report.Packages)
	}

	if got := pkgs["npm|express|4.18.2"]; !got.DirectDependency || got.DependencyDepth != 1 || !got.Reachable {
		t.Fatalf("expected express to be direct depth=1 reachable, got %#v", got)
	}
	if got := pkgs["npm|body-parser|1.20.2"]; got.DirectDependency || got.DependencyDepth != 2 || !got.Reachable {
		t.Fatalf("expected body-parser to be transitive depth=2 reachable, got %#v", got)
	}
	if got := pkgs["npm|lodash|4.17.21"]; !got.DirectDependency || got.DependencyDepth != 1 || got.Reachable {
		t.Fatalf("expected lodash to be direct depth=1 and not reachable, got %#v", got)
	}

	if len(report.SBOM.Dependencies) != 1 {
		t.Fatalf("expected one package dependency edge, got %#v", report.SBOM.Dependencies)
	}
	expressRef := sbomComponentRef(pkgs["npm|express|4.18.2"])
	bodyParserRef := sbomComponentRef(pkgs["npm|body-parser|1.20.2"])
	dep := report.SBOM.Dependencies[0]
	if dep.Ref != expressRef || len(dep.DependsOn) != 1 || dep.DependsOn[0] != bodyParserRef {
		t.Fatalf("expected express -> body-parser dependency, got %#v", dep)
	}
}
