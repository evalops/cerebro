package filesystemanalyzer

import (
	"encoding/json"
	"path"
	"regexp"
	"sort"
	"strings"
)

type npmDependencyGraph struct {
	ManifestPath   string
	BaseDir        string
	Packages       []PackageRecord
	DependencyKeys map[string]map[string]struct{}
	ImportableKeys map[string]map[string]struct{}
}

type npmLockPackage struct {
	Name         string            `json:"name"`
	Version      string            `json:"version"`
	Dependencies map[string]string `json:"dependencies"`
}

type npmLockDocument struct {
	Packages map[string]npmLockPackage `json:"packages"`
}

type npmLockV1Package struct {
	Version      string                      `json:"version"`
	Dependencies map[string]npmLockV1Package `json:"dependencies"`
}

type npmLockV1Document struct {
	Dependencies map[string]npmLockV1Package `json:"dependencies"`
}

var (
	jsRequirePattern    = regexp.MustCompile(`require\(\s*['"]([^'"]+)['"]\s*\)`)
	jsImportFromPattern = regexp.MustCompile(`from\s+['"]([^'"]+)['"]`)
	jsImportBarePattern = regexp.MustCompile(`import\s+['"]([^'"]+)['"]`)
	jsImportCallPattern = regexp.MustCompile(`import\(\s*['"]([^'"]+)['"]\s*\)`)
)

func parseNPMLockPackages(filePath string, data []byte) []PackageRecord {
	graph := parseNPMDependencyGraph(filePath, data)
	if graph == nil {
		return nil
	}
	return graph.Packages
}

func parseNPMDependencyGraph(filePath string, data []byte) *npmDependencyGraph {
	var lock npmLockDocument
	if err := json.Unmarshal(data, &lock); err == nil && len(lock.Packages) > 0 {
		if graph := parseNPMDependencyGraphV2(filePath, lock); graph != nil {
			return graph
		}
	}

	var v1 npmLockV1Document
	if err := json.Unmarshal(data, &v1); err != nil || len(v1.Dependencies) == 0 {
		return nil
	}
	return parseNPMDependencyGraphV1(filePath, v1)
}

func parseNPMDependencyGraphV2(filePath string, lock npmLockDocument) *npmDependencyGraph {
	root, ok := lock.Packages[""]
	if !ok || len(root.Dependencies) == 0 {
		return nil
	}

	baseDir := path.Dir(filePath)
	if baseDir == "." {
		baseDir = ""
	}

	type queueItem struct {
		parentKey  string
		parentPath string
		name       string
		depth      int
	}

	packages := make(map[string]PackageRecord)
	dependencies := make(map[string]map[string]struct{})
	importableKeys := make(map[string]map[string]struct{})
	queue := make([]queueItem, 0, len(root.Dependencies))
	for depName := range root.Dependencies {
		queue = append(queue, queueItem{name: depName, depth: 1})
	}

	for len(queue) > 0 {
		item := queue[0]
		queue = queue[1:]

		resolvedPath, dep, ok := resolveNPMLockPackage(lock.Packages, item.parentPath, item.name)
		if !ok {
			continue
		}
		record := PackageRecord{
			Ecosystem:        "npm",
			Manager:          "npm",
			Name:             firstNonEmpty(strings.TrimSpace(dep.Name), deriveNPMPackageName(resolvedPath)),
			Version:          strings.TrimSpace(dep.Version),
			Location:         filePath,
			DirectDependency: item.depth == 1,
			DependencyDepth:  item.depth,
		}
		if record.Name == "" || record.Version == "" {
			continue
		}
		record.PURL = buildPURL(record)
		key := packageInventoryKey(record)
		if existing, ok := packages[key]; ok {
			packages[key] = mergePackageRecord(existing, record)
		} else {
			packages[key] = record
		}
		if isRootImportableNPMPackagePath(resolvedPath, record.Name) {
			addImportablePackageKey(importableKeys, record.Name, key)
		}
		if item.parentKey != "" {
			if _, ok := dependencies[item.parentKey]; !ok {
				dependencies[item.parentKey] = make(map[string]struct{})
			}
			dependencies[item.parentKey][key] = struct{}{}
		}
		for childName := range dep.Dependencies {
			queue = append(queue, queueItem{
				parentKey:  key,
				parentPath: resolvedPath,
				name:       childName,
				depth:      item.depth + 1,
			})
		}
	}

	if len(packages) == 0 {
		return nil
	}
	out := make([]PackageRecord, 0, len(packages))
	for _, pkg := range packages {
		out = append(out, pkg)
	}
	sort.Slice(out, func(a, b int) bool {
		if out[a].DependencyDepth != out[b].DependencyDepth {
			return out[a].DependencyDepth < out[b].DependencyDepth
		}
		if out[a].Name != out[b].Name {
			return out[a].Name < out[b].Name
		}
		return out[a].Version < out[b].Version
	})
	return &npmDependencyGraph{
		ManifestPath:   filePath,
		BaseDir:        baseDir,
		Packages:       out,
		DependencyKeys: dependencies,
		ImportableKeys: importableKeys,
	}
}

func parseNPMDependencyGraphV1(filePath string, lock npmLockV1Document) *npmDependencyGraph {
	baseDir := path.Dir(filePath)
	if baseDir == "." {
		baseDir = ""
	}

	type queueItem struct {
		parentKey   string
		packagePath string
		name        string
		pkg         npmLockV1Package
		depth       int
	}

	packages := make(map[string]PackageRecord)
	dependencies := make(map[string]map[string]struct{})
	importableKeys := make(map[string]map[string]struct{})
	queue := make([]queueItem, 0, len(lock.Dependencies))
	for depName, dep := range lock.Dependencies {
		queue = append(queue, queueItem{
			name:        depName,
			packagePath: path.Clean("node_modules/" + depName),
			pkg:         dep,
			depth:       1,
		})
	}

	for len(queue) > 0 {
		item := queue[0]
		queue = queue[1:]

		record := PackageRecord{
			Ecosystem:        "npm",
			Manager:          "npm",
			Name:             strings.TrimSpace(item.name),
			Version:          strings.TrimSpace(item.pkg.Version),
			Location:         filePath,
			DirectDependency: item.depth == 1,
			DependencyDepth:  item.depth,
		}
		if record.Name == "" || record.Version == "" {
			continue
		}
		record.PURL = buildPURL(record)
		key := packageInventoryKey(record)
		if existing, ok := packages[key]; ok {
			packages[key] = mergePackageRecord(existing, record)
		} else {
			packages[key] = record
		}
		if isRootImportableNPMPackagePath(item.packagePath, record.Name) {
			addImportablePackageKey(importableKeys, record.Name, key)
		}
		if item.parentKey != "" {
			if _, ok := dependencies[item.parentKey]; !ok {
				dependencies[item.parentKey] = make(map[string]struct{})
			}
			dependencies[item.parentKey][key] = struct{}{}
		}
		for childName, child := range item.pkg.Dependencies {
			queue = append(queue, queueItem{
				parentKey:   key,
				packagePath: path.Clean(item.packagePath + "/node_modules/" + childName),
				name:        childName,
				pkg:         child,
				depth:       item.depth + 1,
			})
		}
	}

	if len(packages) == 0 {
		return nil
	}
	out := make([]PackageRecord, 0, len(packages))
	for _, pkg := range packages {
		out = append(out, pkg)
	}
	sort.Slice(out, func(a, b int) bool {
		if out[a].DependencyDepth != out[b].DependencyDepth {
			return out[a].DependencyDepth < out[b].DependencyDepth
		}
		if out[a].Name != out[b].Name {
			return out[a].Name < out[b].Name
		}
		return out[a].Version < out[b].Version
	})
	return &npmDependencyGraph{
		ManifestPath:   filePath,
		BaseDir:        baseDir,
		Packages:       out,
		DependencyKeys: dependencies,
		ImportableKeys: importableKeys,
	}
}

func resolveNPMLockPackage(packages map[string]npmLockPackage, parentPath, depName string) (string, npmLockPackage, bool) {
	if depName == "" {
		return "", npmLockPackage{}, false
	}
	candidates := make([]string, 0, 2)
	if parentPath != "" {
		candidates = append(candidates, path.Clean(parentPath+"/node_modules/"+depName))
	}
	candidates = append(candidates, "node_modules/"+depName)
	for _, candidate := range candidates {
		if dep, ok := packages[candidate]; ok {
			return candidate, dep, true
		}
	}
	return "", npmLockPackage{}, false
}

func deriveNPMPackageName(packagePath string) string {
	packagePath = strings.TrimSpace(packagePath)
	if packagePath == "" {
		return ""
	}
	parts := strings.Split(packagePath, "/")
	lastNodeModules := -1
	for idx, part := range parts {
		if part == "node_modules" {
			lastNodeModules = idx
		}
	}
	if lastNodeModules >= 0 && lastNodeModules+1 < len(parts) {
		parts = parts[lastNodeModules+1:]
	}
	if len(parts) == 0 {
		return ""
	}
	if strings.HasPrefix(parts[0], "@") && len(parts) > 1 {
		return parts[0] + "/" + parts[1]
	}
	return parts[0]
}

func scanJSImportSpecifiers(data []byte) []string {
	if len(data) == 0 {
		return nil
	}
	text := string(data)
	matches := make([]string, 0)
	for _, pattern := range []*regexp.Regexp{jsRequirePattern, jsImportFromPattern, jsImportBarePattern, jsImportCallPattern} {
		for _, match := range pattern.FindAllStringSubmatch(text, -1) {
			if len(match) < 2 {
				continue
			}
			if pkg := normalizeJSImportPackage(match[1]); pkg != "" {
				matches = append(matches, pkg)
			}
		}
	}
	return dedupeStrings(matches)
}

func normalizeJSImportPackage(specifier string) string {
	specifier = strings.TrimSpace(specifier)
	if specifier == "" || strings.HasPrefix(specifier, ".") || strings.HasPrefix(specifier, "/") {
		return ""
	}
	parts := strings.Split(specifier, "/")
	if len(parts) == 0 {
		return ""
	}
	if strings.HasPrefix(parts[0], "@") {
		if len(parts) < 2 {
			return ""
		}
		return parts[0] + "/" + parts[1]
	}
	return parts[0]
}

func addImportablePackageKey(importableKeys map[string]map[string]struct{}, name, key string) {
	name = strings.TrimSpace(name)
	key = strings.TrimSpace(key)
	if name == "" || key == "" {
		return
	}
	if _, ok := importableKeys[name]; !ok {
		importableKeys[name] = make(map[string]struct{})
	}
	importableKeys[name][key] = struct{}{}
}

func isRootImportableNPMPackagePath(packagePath, packageName string) bool {
	packagePath = strings.TrimSpace(packagePath)
	packageName = strings.TrimSpace(packageName)
	if packagePath == "" || packageName == "" {
		return false
	}
	return path.Clean(packagePath) == path.Clean("node_modules/"+packageName)
}
