package graph

import (
	"testing"
	"time"
)

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

func TestMaterializeOwnershipFacetUsesManagedByOutgoingEdgesForManagers(t *testing.T) {
	now := time.Now().UTC()
	g := New()
	entity := &Node{ID: "service:payments", Kind: NodeKindService, CreatedAt: now, UpdatedAt: now}
	manager := &Node{ID: "person:alice@example.com", Kind: NodeKindPerson, CreatedAt: now, UpdatedAt: now}
	child := &Node{ID: "service:payments-worker", Kind: NodeKindService, CreatedAt: now, UpdatedAt: now}
	owner := &Node{ID: "group:platform", Kind: NodeKindGroup, CreatedAt: now, UpdatedAt: now}
	g.AddNode(entity)
	g.AddNode(manager)
	g.AddNode(child)
	g.AddNode(owner)
	g.AddEdge(&Edge{
		ID:        "manager-edge",
		Source:    entity.ID,
		Target:    manager.ID,
		Kind:      EdgeKindManagedBy,
		Effect:    EdgeEffectAllow,
		CreatedAt: now,
	})
	g.AddEdge(&Edge{
		ID:        "child-edge",
		Source:    child.ID,
		Target:    entity.ID,
		Kind:      EdgeKindManagedBy,
		Effect:    EdgeEffectAllow,
		CreatedAt: now,
	})
	g.AddEdge(&Edge{
		ID:        "owner-edge",
		Source:    owner.ID,
		Target:    entity.ID,
		Kind:      EdgeKindOwns,
		Effect:    EdgeEffectAllow,
		CreatedAt: now,
	})

	def, ok := GetEntityFacetDefinition("ownership")
	if !ok {
		t.Fatal("expected ownership facet definition")
	}

	record, materialized := materializeOwnershipFacet(g, entity, now, now, def, nil)
	if !materialized {
		t.Fatal("expected ownership facet to materialize")
	}
	owners, _ := record.Fields["owner_ids"].([]string)
	managers, _ := record.Fields["manager_ids"].([]string)
	if len(owners) != 1 || owners[0] != owner.ID {
		t.Fatalf("expected owner list to include %q, got %#v", owner.ID, owners)
	}
	if len(managers) != 1 || managers[0] != manager.ID {
		t.Fatalf("expected manager list to include only %q, got %#v", manager.ID, managers)
	}
}
