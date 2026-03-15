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

	if got := pkgs["npm|express|4.18.2"]; !got.DirectDependency || got.DependencyDepth != 1 || !got.Reachable || got.ImportFileCount != 1 {
		t.Fatalf("expected express to be direct depth=1 reachable, got %#v", got)
	}
	if got := pkgs["npm|body-parser|1.20.2"]; got.DirectDependency || got.DependencyDepth != 2 || !got.Reachable || got.ImportFileCount != 1 {
		t.Fatalf("expected body-parser to be transitive depth=2 reachable, got %#v", got)
	}
	if got := pkgs["npm|lodash|4.17.21"]; !got.DirectDependency || got.DependencyDepth != 1 || got.Reachable || got.ImportFileCount != 0 {
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

func TestAnalyzerMarksDirectlyImportedTransitiveNPMPackageReachable(t *testing.T) {
	root := t.TempDir()
	mustWriteFile(t, filepath.Join(root, "srv", "app", "package-lock.json"), `{
  "name": "demo",
  "lockfileVersion": 2,
  "packages": {
    "": {
      "name": "demo",
      "version": "1.0.0",
      "dependencies": {
        "express": "4.18.2"
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
    }
  }
}`)
	mustWriteFile(t, filepath.Join(root, "srv", "app", "src", "index.js"), "const bodyParser = require('body-parser')\napp.use(bodyParser.json())\n")

	report, err := New(Options{}).Analyze(context.Background(), root)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}

	pkg := findPackageRecord(report.Packages, "npm", "body-parser", "1.20.2")
	if pkg == nil {
		t.Fatalf("expected body-parser package in %#v", report.Packages)
	}
	if !pkg.Reachable || pkg.ImportFileCount != 1 {
		t.Fatalf("expected directly imported transitive package to be reachable, got %#v", *pkg)
	}
}

func TestAnalyzerBuildsNPMDependencyGraphFromV1Lockfile(t *testing.T) {
	root := t.TempDir()
	mustWriteFile(t, filepath.Join(root, "srv", "app", "package-lock.json"), `{
  "name": "demo",
  "lockfileVersion": 1,
  "dependencies": {
    "express": {
      "version": "4.18.2",
      "requires": {
        "body-parser": "1.20.2"
      },
      "dependencies": {
        "body-parser": {
          "version": "1.20.2"
        }
      }
    }
  }
}`)
	mustWriteFile(t, filepath.Join(root, "srv", "app", "src", "index.js"), "import express from 'express'\n")

	report, err := New(Options{}).Analyze(context.Background(), root)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}

	express := findPackageRecord(report.Packages, "npm", "express", "4.18.2")
	if express == nil {
		t.Fatalf("expected express package in %#v", report.Packages)
	}
	if !express.DirectDependency || express.DependencyDepth != 1 || !express.Reachable || express.ImportFileCount != 1 {
		t.Fatalf("expected express to be direct depth=1 reachable, got %#v", *express)
	}
	bodyParser := findPackageRecord(report.Packages, "npm", "body-parser", "1.20.2")
	if bodyParser == nil {
		t.Fatalf("expected body-parser package in %#v", report.Packages)
	}
	if bodyParser.DirectDependency || bodyParser.DependencyDepth != 2 || !bodyParser.Reachable || bodyParser.ImportFileCount != 1 {
		t.Fatalf("expected body-parser to be transitive depth=2 reachable, got %#v", *bodyParser)
	}
	if len(report.SBOM.Dependencies) != 1 {
		t.Fatalf("expected one dependency edge, got %#v", report.SBOM.Dependencies)
	}
}

func TestAnalyzerBuildsGoDependencyReachabilityFromGoMod(t *testing.T) {
	root := t.TempDir()
	mustWriteFile(t, filepath.Join(root, "workspace", "go.mod"), `module example.com/demo

go 1.22

require (
	github.com/google/uuid v1.6.0
	golang.org/x/text v0.14.0 // indirect
)
`)
	mustWriteFile(t, filepath.Join(root, "workspace", "go.sum"), `github.com/google/uuid v1.6.0
golang.org/x/text v0.14.0
`)
	mustWriteFile(t, filepath.Join(root, "workspace", "main.go"), `package main

import (
	"fmt"

	"github.com/google/uuid"
)

func main() {
	fmt.Println(uuid.NewString())
}
`)

	report, err := New(Options{}).Analyze(context.Background(), root)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}

	uuid := findPackageRecord(report.Packages, "golang", "github.com/google/uuid", "v1.6.0")
	if uuid == nil {
		t.Fatalf("expected uuid package in %#v", report.Packages)
	}
	if !uuid.DirectDependency || uuid.DependencyDepth != 1 || !uuid.Reachable || uuid.ImportFileCount != 1 {
		t.Fatalf("expected uuid to be direct depth=1 reachable, got %#v", *uuid)
	}

	text := findPackageRecord(report.Packages, "golang", "golang.org/x/text", "v0.14.0")
	if text == nil {
		t.Fatalf("expected x/text package in %#v", report.Packages)
	}
	if text.DirectDependency || text.DependencyDepth != 2 || text.Reachable || text.ImportFileCount != 0 {
		t.Fatalf("expected x/text to be indirect depth=2 and not reachable, got %#v", *text)
	}
}

func TestAnalyzerMarksGoSubpackageImportsReachable(t *testing.T) {
	root := t.TempDir()
	mustWriteFile(t, filepath.Join(root, "workspace", "go.mod"), `module example.com/demo

go 1.22

require golang.org/x/text v0.14.0
`)
	mustWriteFile(t, filepath.Join(root, "workspace", "go.sum"), `golang.org/x/text v0.14.0
`)
	mustWriteFile(t, filepath.Join(root, "workspace", "main.go"), `package main

import "golang.org/x/text/cases"

func main() {
	_ = cases.Title
}
`)

	report, err := New(Options{}).Analyze(context.Background(), root)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}

	text := findPackageRecord(report.Packages, "golang", "golang.org/x/text", "v0.14.0")
	if text == nil {
		t.Fatalf("expected x/text package in %#v", report.Packages)
	}
	if !text.Reachable || text.ImportFileCount != 1 {
		t.Fatalf("expected subpackage import to mark module reachable, got %#v", *text)
	}
}

func findPackageRecord(pkgs []PackageRecord, ecosystem, name, version string) *PackageRecord {
	for i := range pkgs {
		pkg := &pkgs[i]
		if pkg.Ecosystem == ecosystem && pkg.Name == name && pkg.Version == version {
			return pkg
		}
	}
	return nil
}
