package imagescan

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/evalops/cerebro/internal/scanner"
	"github.com/evalops/cerebro/internal/webhooks"
)

type fakeRegistry struct {
	name     string
	host     string
	manifest *scanner.ImageManifest
	vulns    []scanner.ImageVulnerability
	blobs    map[string][]byte
}

func (r *fakeRegistry) Name() string { return r.name }
func (r *fakeRegistry) RegistryHost() string {
	return r.host
}
func (r *fakeRegistry) QualifyImageRef(repo, tag string) string {
	return r.host + "/" + repo + ":" + tag
}
func (r *fakeRegistry) ListRepositories(context.Context) ([]scanner.Repository, error) {
	return nil, nil
}
func (r *fakeRegistry) ListTags(context.Context, string) ([]scanner.ImageTag, error) {
	return nil, nil
}
func (r *fakeRegistry) GetManifest(context.Context, string, string) (*scanner.ImageManifest, error) {
	return r.manifest, nil
}
func (r *fakeRegistry) GetVulnerabilities(context.Context, string, string) ([]scanner.ImageVulnerability, error) {
	return append([]scanner.ImageVulnerability(nil), r.vulns...), nil
}
func (r *fakeRegistry) DownloadBlob(_ context.Context, _ string, digest string) (io.ReadCloser, error) {
	data, ok := r.blobs[digest]
	if !ok {
		return nil, fmt.Errorf("blob %s not found", digest)
	}
	return io.NopCloser(bytes.NewReader(data)), nil
}

type fakeFilesystemScanner struct {
	result *scanner.ContainerScanResult
	err    error
}

func (s fakeFilesystemScanner) ScanFilesystem(_ context.Context, _ string) (*scanner.ContainerScanResult, error) {
	if s.err != nil {
		return nil, s.err
	}
	return s.result, nil
}

type captureEmitter struct {
	events []webhooks.EventType
}

func (e *captureEmitter) EmitWithErrors(_ context.Context, eventType webhooks.EventType, _ map[string]interface{}) error {
	e.events = append(e.events, eventType)
	return nil
}

func TestSQLiteRunStoreRoundTripAndEvents(t *testing.T) {
	store, err := NewSQLiteRunStore(filepath.Join(t.TempDir(), "image-scan.db"))
	if err != nil {
		t.Fatalf("new sqlite run store: %v", err)
	}
	defer func() { _ = store.Close() }()

	now := time.Now().UTC()
	run := &RunRecord{
		ID:          "image_scan:test",
		Registry:    RegistryECR,
		Status:      RunStatusRunning,
		Stage:       RunStageAnalyze,
		Target:      ScanTarget{Registry: RegistryECR, Repository: "repo", Tag: "latest"},
		SubmittedAt: now,
		UpdatedAt:   now,
	}
	if err := store.SaveRun(context.Background(), run); err != nil {
		t.Fatalf("save run: %v", err)
	}
	event, err := store.AppendEvent(context.Background(), run.ID, RunEvent{
		Status:     run.Status,
		Stage:      run.Stage,
		Message:    "analysis started",
		RecordedAt: now,
	})
	if err != nil {
		t.Fatalf("append event: %v", err)
	}
	if event.Sequence != 1 {
		t.Fatalf("expected first event sequence 1, got %d", event.Sequence)
	}
	loaded, err := store.LoadRun(context.Background(), run.ID)
	if err != nil {
		t.Fatalf("load run: %v", err)
	}
	if loaded == nil || loaded.ID != run.ID {
		t.Fatalf("expected loaded run %q, got %#v", run.ID, loaded)
	}
	events, err := store.LoadEvents(context.Background(), run.ID)
	if err != nil {
		t.Fatalf("load events: %v", err)
	}
	if len(events) != 1 || events[0].Message != "analysis started" {
		t.Fatalf("unexpected stored events: %#v", events)
	}
}

func TestLocalMaterializerAppliesWhiteouts(t *testing.T) {
	layer1 := gzipTarLayer(t, map[string]string{
		"etc/os-release": "NAME=Ubuntu\n",
		"tmp/old.txt":    "old\n",
	}, nil)
	layer2 := gzipTarLayer(t, map[string]string{
		"tmp/new.txt": "new\n",
	}, []string{"tmp/.wh.old.txt"})

	manifest := &scanner.ImageManifest{
		Layers: []scanner.Layer{
			{Digest: "sha256:one", MediaType: "application/vnd.oci.image.layer.v1.tar+gzip"},
			{Digest: "sha256:two", MediaType: "application/vnd.oci.image.layer.v1.tar+gzip"},
		},
	}
	materializer := NewLocalMaterializer(filepath.Join(t.TempDir(), "rootfs"))
	artifact, _, err := materializer.Materialize(context.Background(), "image_scan:test", manifest, func(_ context.Context, digest string) (io.ReadCloser, error) {
		switch digest {
		case "sha256:one":
			return io.NopCloser(bytes.NewReader(layer1)), nil
		case "sha256:two":
			return io.NopCloser(bytes.NewReader(layer2)), nil
		default:
			return nil, fmt.Errorf("unexpected digest %s", digest)
		}
	})
	if err != nil {
		t.Fatalf("materialize: %v", err)
	}
	if _, err := os.Stat(filepath.Join(artifact.Path, "etc", "os-release")); err != nil {
		t.Fatalf("expected os-release to exist: %v", err)
	}
	if _, err := os.Stat(filepath.Join(artifact.Path, "tmp", "old.txt")); !os.IsNotExist(err) {
		t.Fatalf("expected old.txt to be removed by whiteout, got %v", err)
	}
	if _, err := os.Stat(filepath.Join(artifact.Path, "tmp", "new.txt")); err != nil {
		t.Fatalf("expected new.txt to exist: %v", err)
	}
}

func TestRunnerRunImageScanPersistsLifecycleAndCleanup(t *testing.T) {
	store, err := NewSQLiteRunStore(filepath.Join(t.TempDir(), "image-scan.db"))
	if err != nil {
		t.Fatalf("new sqlite run store: %v", err)
	}
	defer func() { _ = store.Close() }()

	layer := gzipTarLayer(t, map[string]string{
		"etc/os-release": "NAME=Ubuntu\n",
	}, nil)
	registry := &fakeRegistry{
		name: "ecr",
		host: "123456789012.dkr.ecr.us-east-1.amazonaws.com",
		manifest: &scanner.ImageManifest{
			Digest:       "sha256:image",
			ConfigDigest: "sha256:config",
			Config: scanner.ImageConfig{
				OS:           "linux",
				Architecture: "amd64",
			},
			Layers: []scanner.Layer{
				{Digest: "sha256:layer", MediaType: "application/vnd.oci.image.layer.v1.tar+gzip"},
			},
		},
		vulns: []scanner.ImageVulnerability{{
			CVE:              "CVE-2024-0001",
			Severity:         "high",
			Package:          "openssl",
			InstalledVersion: "1.0.0",
		}},
		blobs: map[string][]byte{
			"sha256:layer": layer,
		},
	}
	emitter := &captureEmitter{}
	runner := NewRunner(RunnerOptions{
		Store:        store,
		Registries:   []scanner.RegistryClient{registry},
		Materializer: NewLocalMaterializer(filepath.Join(t.TempDir(), "rootfs")),
		Analyzer: FilesystemAnalyzer{
			Scanner: fakeFilesystemScanner{
				result: &scanner.ContainerScanResult{
					Vulnerabilities: []scanner.ImageVulnerability{{
						CVE:              "CVE-2024-0002",
						Severity:         "critical",
						Package:          "glibc",
						InstalledVersion: "2.31",
					}},
				},
			},
		},
		Events: emitter,
	})

	run, err := runner.RunImageScan(context.Background(), ScanRequest{
		ID: "image_scan:success",
		Target: ScanTarget{
			Registry:   RegistryECR,
			Repository: "repo",
			Tag:        "latest",
		},
	})
	if err != nil {
		t.Fatalf("run image scan: %v", err)
	}
	if run.Status != RunStatusSucceeded {
		t.Fatalf("expected succeeded run, got %s", run.Status)
	}
	if run.Analysis == nil {
		t.Fatal("expected analysis report to be persisted")
	}
	if run.Analysis.Result.Summary.Total != 2 {
		t.Fatalf("expected merged vulnerabilities total 2, got %#v", run.Analysis.Result.Summary)
	}
	if run.Filesystem == nil || run.Filesystem.CleanedUpAt == nil {
		t.Fatalf("expected filesystem artifact to be cleaned up, got %#v", run.Filesystem)
	}
	if len(emitter.events) != 2 || emitter.events[0] != webhooks.EventSecurityImageScanStarted || emitter.events[1] != webhooks.EventSecurityImageScanCompleted {
		t.Fatalf("unexpected emitted events: %#v", emitter.events)
	}
	loaded, err := store.LoadRun(context.Background(), run.ID)
	if err != nil {
		t.Fatalf("load run: %v", err)
	}
	if loaded == nil || loaded.Status != RunStatusSucceeded {
		t.Fatalf("expected persisted succeeded run, got %#v", loaded)
	}
	events, err := store.LoadEvents(context.Background(), run.ID)
	if err != nil {
		t.Fatalf("load events: %v", err)
	}
	if len(events) < 3 {
		t.Fatalf("expected multiple lifecycle events, got %#v", events)
	}
}

func gzipTarLayer(t *testing.T, files map[string]string, extraEntries []string) []byte {
	t.Helper()
	var archive bytes.Buffer
	gz := gzip.NewWriter(&archive)
	tw := tar.NewWriter(gz)
	for name, content := range files {
		data := []byte(content)
		header := &tar.Header{
			Name: name,
			Mode: 0o644,
			Size: int64(len(data)),
		}
		if err := tw.WriteHeader(header); err != nil {
			t.Fatalf("write tar header %s: %v", name, err)
		}
		if _, err := tw.Write(data); err != nil {
			t.Fatalf("write tar content %s: %v", name, err)
		}
	}
	for _, name := range extraEntries {
		header := &tar.Header{
			Name: name,
			Mode: 0o000,
			Size: 0,
		}
		if err := tw.WriteHeader(header); err != nil {
			t.Fatalf("write whiteout header %s: %v", name, err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("close tar: %v", err)
	}
	if err := gz.Close(); err != nil {
		t.Fatalf("close gzip: %v", err)
	}
	return archive.Bytes()
}
