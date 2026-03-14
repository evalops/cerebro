package remediation

import "testing"

func TestPublicStorageAccessStillEnabled_ParsesResourceJSON(t *testing.T) {
	execution := &Execution{
		TriggerData: map[string]any{
			"resource_json": `{"public_access":"true"}`,
		},
	}

	public, detail := publicStorageAccessStillEnabled(execution)
	if !public {
		t.Fatalf("public = false, want true (detail=%q)", detail)
	}
}

func TestPublicSecurityGroupIngressMatchesRuleRows(t *testing.T) {
	execution := &Execution{
		TriggerData: map[string]any{
			"policy_id": "aws-security-group-restrict-rdp",
			"direction": "ingress",
			"protocol":  "tcp",
			"from_port": 3389,
			"to_port":   3389,
			"ip_ranges": []any{
				map[string]any{"CidrIp": "0.0.0.0/0"},
			},
		},
	}

	matches, detail := publicSecurityGroupIngressMatches(execution)
	if len(matches) != 1 {
		t.Fatalf("matches = %#v, want one match (detail=%q)", matches, detail)
	}
	if matches[0]["from_port"] != 3389 {
		t.Fatalf("unexpected match payload: %#v", matches[0])
	}
}
