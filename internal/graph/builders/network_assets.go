package builders

import "strings"

func awsSecurityGroupNodeID(record map[string]any) string {
	return firstNonEmpty(queryRowString(record, "arn"), queryRowString(record, "_cq_id"), queryRowString(record, "group_id"))
}

func awsSecurityGroupNodeFromRecord(record map[string]any, provider, account, region string) *Node {
	id := awsSecurityGroupNodeID(record)
	if id == "" {
		return nil
	}
	public := awsSecurityGroupAllowsInternet(queryRow(record, "ip_permissions"))
	risk := RiskNone
	if public {
		risk = RiskHigh
	}
	return &Node{
		ID:       id,
		Kind:     NodeKindNetwork,
		Name:     firstNonEmpty(queryRowString(record, "group_name"), queryRowString(record, "group_id"), id),
		Provider: firstNonEmpty(provider, "aws"),
		Account:  firstNonEmpty(queryRowString(record, "account_id"), account),
		Region:   firstNonEmpty(queryRowString(record, "region"), region),
		Risk:     risk,
		Properties: map[string]any{
			"network_kind":          "security_group",
			"group_id":              queryRow(record, "group_id"),
			"group_name":            queryRow(record, "group_name"),
			"description":           queryRow(record, "description"),
			"vpc_id":                queryRow(record, "vpc_id"),
			"ip_permissions":        queryRow(record, "ip_permissions"),
			"ip_permissions_egress": queryRow(record, "ip_permissions_egress"),
			"public":                public,
		},
	}
}

func gcpFirewallNodeID(record map[string]any) string {
	return firstNonEmpty(queryRowString(record, "self_link"), queryRowString(record, "_cq_id"), queryRowString(record, "id"), queryRowString(record, "name"))
}

func gcpFirewallNodeFromRecord(record map[string]any, provider, account, region string) *Node {
	id := gcpFirewallNodeID(record)
	if id == "" {
		return nil
	}
	public := gcpFirewallAllowsInternet(record)
	risk := RiskNone
	if public {
		risk = RiskHigh
	}
	return &Node{
		ID:       id,
		Kind:     NodeKindNetwork,
		Name:     firstNonEmpty(queryRowString(record, "name"), id),
		Provider: firstNonEmpty(provider, "gcp"),
		Account:  firstNonEmpty(queryRowString(record, "project_id"), account),
		Region:   firstNonEmpty(queryRowString(record, "location"), queryRowString(record, "region"), region),
		Risk:     risk,
		Properties: map[string]any{
			"network_kind":  "firewall",
			"network":       queryRow(record, "network"),
			"direction":     queryRow(record, "direction"),
			"source_ranges": queryRow(record, "source_ranges"),
			"allowed":       queryRow(record, "allowed"),
			"denied":        queryRow(record, "denied"),
			"disabled":      queryRow(record, "disabled"),
			"public":        public,
		},
	}
}

func azureNetworkSecurityGroupNodeID(record map[string]any) string {
	return firstNonEmpty(queryRowString(record, "id"), queryRowString(record, "_cq_id"), queryRowString(record, "name"))
}

func azureNetworkSecurityGroupNodeFromRecord(record map[string]any, provider, account, region string) *Node {
	id := azureNetworkSecurityGroupNodeID(record)
	if id == "" {
		return nil
	}
	public := azureNetworkSecurityGroupAllowsInternet(record)
	risk := RiskNone
	if public {
		risk = RiskHigh
	}
	return &Node{
		ID:       id,
		Kind:     NodeKindNetwork,
		Name:     firstNonEmpty(queryRowString(record, "name"), id),
		Provider: firstNonEmpty(provider, "azure"),
		Account:  firstNonEmpty(queryRowString(record, "subscription_id"), account),
		Region:   firstNonEmpty(queryRowString(record, "location"), region),
		Risk:     risk,
		Properties: map[string]any{
			"network_kind":           "network_security_group",
			"resource_group":         queryRow(record, "resource_group"),
			"security_rules":         queryRow(record, "security_rules"),
			"default_security_rules": queryRow(record, "default_security_rules"),
			"public":                 public,
		},
	}
}

func awsSecurityGroupAllowsInternet(value any) bool {
	return containsInternetCIDR(strings.ToLower(toString(value)))
}

func gcpFirewallAllowsInternet(record map[string]any) bool {
	if toBool(queryRow(record, "disabled")) {
		return false
	}
	direction := strings.ToUpper(strings.TrimSpace(queryRowString(record, "direction")))
	if direction != "INGRESS" {
		return false
	}
	return containsInternetCIDR(strings.ToLower(toString(queryRow(record, "source_ranges"))))
}

func azureNetworkSecurityGroupAllowsInternet(record map[string]any) bool {
	rules := strings.ToLower(toString(queryRow(record, "security_rules")))
	if rules == "" {
		rules = strings.ToLower(toString(queryRow(record, "default_security_rules")))
	}
	if rules == "" {
		return false
	}
	if !strings.Contains(rules, "allow") || !strings.Contains(rules, "inbound") {
		return false
	}
	return containsInternetCIDR(rules) ||
		strings.Contains(rules, "internet") ||
		strings.Contains(rules, "\"*\"") ||
		strings.Contains(rules, "sourceaddressprefix:*") ||
		strings.Contains(rules, "source_address_prefix:*")
}

func containsInternetCIDR(value string) bool {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return false
	}
	return strings.Contains(value, "0.0.0.0/0") || strings.Contains(value, "::/0")
}
