package graph

import "testing"

func TestGetEntityFacetDefinitionReturnsDeepCopy(t *testing.T) {
	def, ok := GetEntityFacetDefinition("ownership")
	if !ok {
		t.Fatal("expected ownership facet definition")
	}
	if len(def.ClaimPredicates) == 0 {
		t.Fatalf("expected cloned definition to retain claim predicates, got %#v", def)
	}
	original := def.ClaimPredicates[0]
	def.ClaimPredicates[0] = "mutated"

	again, ok := GetEntityFacetDefinition("ownership")
	if !ok {
		t.Fatal("expected ownership facet definition on second lookup")
	}
	if again.ClaimPredicates[0] != original {
		t.Fatalf("expected registry definition to be isolated from caller mutation, got %#v", again)
	}
}
