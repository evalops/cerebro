package vulndb

import "testing"

func TestDistributionVersionMatchesNonNumericVersions(t *testing.T) {
	if distributionVersionMatches("focal", "bionic") {
		t.Fatal("expected different codenames not to match")
	}
	if !distributionVersionMatches("focal", "focal") {
		t.Fatal("expected identical codenames to match")
	}
}
