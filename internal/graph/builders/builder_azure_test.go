package builders

import (
	"context"
	"log/slog"
	"os"
	"testing"
)

func TestBuilder_AzureBuildsScopesRBACPoliciesAndVaultEdges(t *testing.T) {
	t.Parallel()

	source := newMockDataSource()
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))

	source.setResult(`SELECT id, display_name, app_id, service_principal_type, account_enabled, app_owner_organization_id, publisher_name, created_date_time, tags, subscription_id FROM azure_graph_service_principals`, &DataQueryResult{
		Rows: []map[string]any{{
			"id":                     "sp-managed",
			"display_name":           "vm-managed-identity",
			"app_id":                 "app-1",
			"service_principal_type": "ManagedIdentity",
			"subscription_id":        "sub-1",
		}},
	})
	source.setResult(`SELECT id, user_principal_name, display_name, mail, department, job_title, account_enabled, user_type, last_sign_in_datetime FROM entra_users`, &DataQueryResult{
		Rows: []map[string]any{{
			"id":                  "user-1",
			"user_principal_name": "alice@example.com",
			"display_name":        "Alice",
			"mail":                "alice@example.com",
		}},
	})
	source.setResult(`SELECT id, name, subscription_id, resource_group, location, vm_size, os_type, provisioning_state, identity FROM azure_compute_virtual_machines`, &DataQueryResult{
		Rows: []map[string]any{{
			"id":                 "/subscriptions/sub-1/resourceGroups/rg-app/providers/Microsoft.Compute/virtualMachines/vm-1",
			"name":               "vm-1",
			"subscription_id":    "sub-1",
			"resource_group":     "rg-app",
			"location":           "eastus",
			"identity":           map[string]any{"principal_id": "sp-managed"},
			"vm_size":            "Standard_D2s_v5",
			"os_type":            "Linux",
			"provisioning_state": "Succeeded",
		}},
	})
	source.setResult(`SELECT id, name, subscription_id, resource_group, location, security_rules, default_security_rules FROM azure_network_security_groups`, &DataQueryResult{
		Rows: []map[string]any{{
			"id":              "/subscriptions/sub-1/resourceGroups/rg-app/providers/Microsoft.Network/networkSecurityGroups/nsg-1",
			"name":            "nsg-1",
			"subscription_id": "sub-1",
			"resource_group":  "rg-app",
			"location":        "eastus",
			"security_rules": []any{
				map[string]any{
					"direction":             "Inbound",
					"access":                "Allow",
					"source_address_prefix": "0.0.0.0/0",
				},
			},
		}},
	})
	source.setResult(`SELECT id, name, subscription_id, resource_group, location, tenant_id, vault_uri, access_policies, enable_purge_protection, enable_soft_delete FROM azure_keyvault_vaults`, &DataQueryResult{
		Rows: []map[string]any{{
			"id":              "/subscriptions/sub-1/resourceGroups/rg-app/providers/Microsoft.KeyVault/vaults/vault-1",
			"name":            "vault-1",
			"subscription_id": "sub-1",
			"resource_group":  "rg-app",
			"location":        "eastus",
			"tenant_id":       "tenant-1",
			"vault_uri":       "https://vault-1.vault.azure.net/",
			"access_policies": []any{
				map[string]any{
					"object_id": "sp-managed",
					"permissions": map[string]any{
						"secrets": []any{"get", "set"},
					},
				},
			},
		}},
	})
	source.setResult(`SELECT id, name, subscription_id, vault_uri, managed, attributes FROM azure_keyvault_keys`, &DataQueryResult{
		Rows: []map[string]any{{
			"id":              "/subscriptions/sub-1/resourceGroups/rg-app/providers/Microsoft.KeyVault/vaults/vault-1/keys/key-1",
			"name":            "key-1",
			"subscription_id": "sub-1",
			"vault_uri":       "https://vault-1.vault.azure.net/",
		}},
	})
	source.setResult(`SELECT id, name, subscription_id, location, display_name, scope, policy_definition_id, enforcement_mode, identity, metadata, parameters FROM azure_policy_assignments`, &DataQueryResult{
		Rows: []map[string]any{{
			"id":                   "/subscriptions/sub-1/providers/Microsoft.Authorization/policyAssignments/pa-1",
			"name":                 "pa-1",
			"display_name":         "Require Tags",
			"subscription_id":      "sub-1",
			"location":             "eastus",
			"scope":                "/subscriptions/sub-1",
			"policy_definition_id": "/providers/Microsoft.Authorization/policyDefinitions/pd-1",
			"identity":             map[string]any{"principal_id": "sp-managed"},
		}},
	})
	source.setResult(`SELECT id, scope, subscription_id FROM azure_policy_assignments`, &DataQueryResult{
		Rows: []map[string]any{{
			"id":              "/subscriptions/sub-1/providers/Microsoft.Authorization/policyAssignments/pa-1",
			"scope":           "/subscriptions/sub-1",
			"subscription_id": "sub-1",
		}},
	})
	source.setResult(`SELECT id, principal_id, principal_type, role_definition_id, scope, condition, can_delegate, delegated_managed_identity_id, description, subscription_id FROM azure_rbac_role_assignments`, &DataQueryResult{
		Rows: []map[string]any{{
			"id":                 "ra-1",
			"principal_id":       "sp-managed",
			"principal_type":     "ServicePrincipal",
			"role_definition_id": "/subscriptions/sub-1/providers/Microsoft.Authorization/roleDefinitions/8e3af657-a8ff-443c-a75c-2fe8c4bcb635",
			"scope":              "/subscriptions/sub-1",
			"subscription_id":    "sub-1",
		}},
	})
	source.setResult(`SELECT id, vault_uri, access_policies FROM azure_keyvault_vaults`, &DataQueryResult{
		Rows: []map[string]any{{
			"id":        "/subscriptions/sub-1/resourceGroups/rg-app/providers/Microsoft.KeyVault/vaults/vault-1",
			"vault_uri": "https://vault-1.vault.azure.net/",
			"access_policies": []any{
				map[string]any{
					"object_id": "sp-managed",
					"permissions": map[string]any{
						"secrets": []any{"get", "set"},
					},
				},
			},
		}},
	})
	source.setResult(`SELECT id, principal_id, role_definition_id, directory_scope_id FROM entra_role_assignments`, &DataQueryResult{
		Rows: []map[string]any{{
			"id":                 "entra-ra-1",
			"principal_id":       "user-1",
			"role_definition_id": "role-global-admin",
			"directory_scope_id": "/",
		}},
	})
	source.setResult(`SELECT id, display_name FROM entra_directory_roles`, &DataQueryResult{
		Rows: []map[string]any{{
			"id":           "role-global-admin",
			"display_name": "Global Administrator",
		}},
	})

	builder := NewBuilder(source, logger)
	if err := builder.Build(context.Background()); err != nil {
		t.Fatalf("build failed: %v", err)
	}

	g := builder.Graph()
	vmID := "/subscriptions/sub-1/resourceGroups/rg-app/providers/Microsoft.Compute/virtualMachines/vm-1"
	rgID := "/subscriptions/sub-1/resourceGroups/rg-app"
	subscriptionID := "/subscriptions/sub-1"
	vaultID := "/subscriptions/sub-1/resourceGroups/rg-app/providers/Microsoft.KeyVault/vaults/vault-1"
	keyID := "/subscriptions/sub-1/resourceGroups/rg-app/providers/Microsoft.KeyVault/vaults/vault-1/keys/key-1"
	policyID := "/subscriptions/sub-1/providers/Microsoft.Authorization/policyAssignments/pa-1"
	roleNodeID := "azure_rbac_role:8e3af657-a8ff-443c-a75c-2fe8c4bcb635"
	directoryRoleNodeID := "azure_directory_role:role-global-admin"
	nsgID := "/subscriptions/sub-1/resourceGroups/rg-app/providers/Microsoft.Network/networkSecurityGroups/nsg-1"

	if node, ok := g.GetNode(subscriptionID); !ok || node.Kind != NodeKindProject {
		t.Fatalf("expected Azure subscription scope node, got %#v", node)
	}
	if node, ok := g.GetNode(rgID); !ok || node.Kind != NodeKindFolder {
		t.Fatalf("expected Azure resource group scope node, got %#v", node)
	}
	if node, ok := g.GetNode(roleNodeID); !ok || node.Kind != NodeKindRole {
		t.Fatalf("expected Azure RBAC role node, got %#v", node)
	}
	if node, ok := g.GetNode(directoryRoleNodeID); !ok || node.Kind != NodeKindRole {
		t.Fatalf("expected Entra directory role node, got %#v", node)
	}

	assertEdgeExists(t, g, vmID, "sp-managed", EdgeKindCanAssume)
	assertEdgeExists(t, g, vmID, rgID, EdgeKindLocatedIn)
	assertEdgeExists(t, g, rgID, subscriptionID, EdgeKindLocatedIn)
	assertEdgeExists(t, g, "sp-managed", roleNodeID, EdgeKindMemberOf)
	assertEdgeExists(t, g, roleNodeID, subscriptionID, EdgeKindLocatedIn)
	assertEdgeExists(t, g, "sp-managed", vmID, EdgeKindCanAdmin)
	assertEdgeExists(t, g, policyID, subscriptionID, EdgeKindLocatedIn)
	assertEdgeExists(t, g, policyID, "sp-managed", EdgeKindCanAssume)
	assertEdgeExists(t, g, "sp-managed", vaultID, EdgeKindCanWrite)
	assertEdgeExists(t, g, "sp-managed", keyID, EdgeKindCanWrite)
	assertEdgeExists(t, g, "user-1", directoryRoleNodeID, EdgeKindMemberOf)
	assertEdgeExists(t, g, directoryRoleNodeID, azureTenantRootNodeID, EdgeKindLocatedIn)
	assertEdgeExists(t, g, "internet", nsgID, EdgeKindExposedTo)

	spNode, ok := g.GetNode("sp-managed")
	if !ok {
		t.Fatal("expected managed identity service principal node")
	}
	assignments, _ := spNode.Properties["role_assignments"].([]any)
	if len(assignments) != 1 {
		t.Fatalf("expected one RBAC role assignment on managed identity, got %#v", spNode.Properties["role_assignments"])
	}
}

func TestBuilder_AzureRelationshipEdgesCreatePlaceholderNodes(t *testing.T) {
	t.Parallel()

	source := newMockDataSource()
	builder := NewBuilder(source, nil)

	source.setResult(`
		SELECT source_id, source_type, target_id, target_type, rel_type, properties
		FROM resource_relationships
	`, &DataQueryResult{
		Rows: []map[string]any{{
			"source_id":   "/subscriptions/sub-1/resourceGroups/rg-app/providers/Microsoft.Network/publicIPAddresses/pip-1",
			"source_type": "azure:network:public_ip",
			"target_id":   "/subscriptions/sub-1/resourceGroups/rg-app/providers/Microsoft.Network/networkInterfaces/nic-1",
			"target_type": "azure:network:interface",
			"rel_type":    "ATTACHED_TO",
		}},
	})

	if err := builder.Build(context.Background()); err != nil {
		t.Fatalf("build failed: %v", err)
	}

	publicIP, ok := builder.Graph().GetNode("/subscriptions/sub-1/resourceGroups/rg-app/providers/Microsoft.Network/publicIPAddresses/pip-1")
	if !ok || publicIP.Kind != NodeKindNetwork || publicIP.Provider != "azure" {
		t.Fatalf("expected placeholder Azure public IP node, got %#v", publicIP)
	}
	nic, ok := builder.Graph().GetNode("/subscriptions/sub-1/resourceGroups/rg-app/providers/Microsoft.Network/networkInterfaces/nic-1")
	if !ok || nic.Kind != NodeKindNetwork || nic.Provider != "azure" {
		t.Fatalf("expected placeholder Azure NIC node, got %#v", nic)
	}
	assertEdgeExists(t, builder.Graph(), publicIP.ID, nic.ID, EdgeKindConnectsTo)
}

func TestCDCEventToNode_AzureModernTables(t *testing.T) {
	t.Parallel()

	spNode := cdcEventToNode("azure_graph_service_principals", cdcEvent{
		ResourceID: "sp-managed",
		Payload: map[string]any{
			"id":                     "sp-managed",
			"display_name":           "vm-managed-identity",
			"service_principal_type": "ManagedIdentity",
			"subscription_id":        "sub-1",
		},
	})
	if spNode == nil || spNode.Kind != NodeKindServiceAccount {
		t.Fatalf("expected service account node from Azure graph service principal, got %#v", spNode)
	}
	if got := queryRowString(spNode.Properties, "identity_type"); got != "ManagedIdentity" {
		t.Fatalf("expected managed identity marker on service principal, got %#v", spNode.Properties)
	}

	policyNode := cdcEventToNode("azure_policy_assignments", cdcEvent{
		ResourceID: "/subscriptions/sub-1/providers/Microsoft.Authorization/policyAssignments/pa-1",
		Payload: map[string]any{
			"id":                   "/subscriptions/sub-1/providers/Microsoft.Authorization/policyAssignments/pa-1",
			"display_name":         "Require Tags",
			"subscription_id":      "sub-1",
			"scope":                "/subscriptions/sub-1",
			"policy_definition_id": "/providers/Microsoft.Authorization/policyDefinitions/pd-1",
		},
	})
	if policyNode == nil || policyNode.Kind != NodeKindService {
		t.Fatalf("expected policy assignment service node, got %#v", policyNode)
	}
	if got := queryRowString(policyNode.Properties, "scope"); got != "/subscriptions/sub-1" {
		t.Fatalf("expected policy assignment scope to be preserved, got %#v", policyNode.Properties)
	}
}
