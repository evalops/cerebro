package graph

import "testing"

func TestNormalizeScaleProfileSpec(t *testing.T) {
	spec := NormalizeScaleProfileSpec(ScaleProfileSpec{
		Tiers:           []int{10000, 1000, -1, 1000, 50000},
		QueryIterations: 0,
	})
	if spec.QueryIterations != defaultScaleProfileQueryIterations {
		t.Fatalf("expected default query iterations, got %d", spec.QueryIterations)
	}
	expected := []int{1000, 10000, 50000}
	if len(spec.Tiers) != len(expected) {
		t.Fatalf("unexpected tiers: %#v", spec.Tiers)
	}
	for i := range expected {
		if spec.Tiers[i] != expected[i] {
			t.Fatalf("unexpected tier at %d: got %d want %d", i, spec.Tiers[i], expected[i])
		}
	}
}

func TestProfileSyntheticScaleSmallTier(t *testing.T) {
	report, err := ProfileSyntheticScale(ScaleProfileSpec{
		Tiers:           []int{24},
		QueryIterations: 1,
	})
	if err != nil {
		t.Fatalf("unexpected profile error: %v", err)
	}
	if report == nil {
		t.Fatal("expected report")
	}
	if len(report.Measurements) != 1 {
		t.Fatalf("expected one measurement, got %d", len(report.Measurements))
	}
	measurement := report.Measurements[0]
	if measurement.ResourceCount != 24 {
		t.Fatalf("unexpected resource count: %d", measurement.ResourceCount)
	}
	if measurement.NodeCount <= 0 || measurement.EdgeCount <= 0 {
		t.Fatalf("expected non-zero topology, got nodes=%d edges=%d", measurement.NodeCount, measurement.EdgeCount)
	}
	if measurement.SearchResultCount <= 0 || measurement.SuggestResultCount <= 0 {
		t.Fatalf("expected search/suggest results, got search=%d suggest=%d", measurement.SearchResultCount, measurement.SuggestResultCount)
	}
	if measurement.BlastRadiusReachableCount <= 0 {
		t.Fatalf("expected blast radius reachability, got %d", measurement.BlastRadiusReachableCount)
	}
	if measurement.SnapshotCompressedBytes <= 0 {
		t.Fatalf("expected compressed snapshot bytes, got %d", measurement.SnapshotCompressedBytes)
	}
	if report.RecommendedPath == "" || report.Recommendation == "" {
		t.Fatalf("expected recommendation, got path=%q recommendation=%q", report.RecommendedPath, report.Recommendation)
	}
}

func TestBuildSyntheticScaleGraphFixture(t *testing.T) {
	g, fixture := buildSyntheticScaleGraph(32)
	if g == nil {
		t.Fatal("expected graph")
	}
	if fixture.principalID == "" || fixture.mutationNodeID == "" {
		t.Fatalf("expected populated fixture IDs, got %+v", fixture)
	}
	if _, ok := g.GetNode(fixture.principalID); !ok {
		t.Fatalf("expected principal node %s", fixture.principalID)
	}
	if _, ok := g.GetNode(fixture.mutationNodeID); !ok {
		t.Fatalf("expected mutation node %s", fixture.mutationNodeID)
	}
	if g.NodeCount() <= 32 {
		t.Fatalf("expected topology richer than raw resource count, got %d nodes", g.NodeCount())
	}
}
