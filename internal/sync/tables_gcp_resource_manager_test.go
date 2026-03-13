package sync

import (
	"context"
	"fmt"
	"testing"

	iampb "cloud.google.com/go/iam/apiv1/iampb"
	"cloud.google.com/go/resourcemanager/apiv3/resourcemanagerpb"
	"google.golang.org/api/iterator"
)

type fakeProjectIterator struct {
	projects []*resourcemanagerpb.Project
	index    int
}

func (f *fakeProjectIterator) Next() (*resourcemanagerpb.Project, error) {
	if f.index >= len(f.projects) {
		return nil, iterator.Done
	}
	project := f.projects[f.index]
	f.index++
	return project, nil
}

type fakeResourceManagerProjectsClient struct {
	projects []*resourcemanagerpb.Project
}

func (f fakeResourceManagerProjectsClient) SearchProjects(ctx context.Context, query string) gcpProjectSearchIterator {
	_ = ctx
	_ = query
	return &fakeProjectIterator{projects: f.projects}
}

func (f fakeResourceManagerProjectsClient) GetIAMPolicy(ctx context.Context, resource string) (*iampb.Policy, error) {
	_ = ctx
	_ = resource
	return &iampb.Policy{}, nil
}

func (f fakeResourceManagerProjectsClient) Close() error { return nil }

type fakeResourceManagerFoldersClient struct {
	folders  map[string]*resourcemanagerpb.Folder
	policies map[string]*iampb.Policy
}

func (f fakeResourceManagerFoldersClient) GetFolder(ctx context.Context, resource string) (*resourcemanagerpb.Folder, error) {
	_ = ctx
	folder, ok := f.folders[resource]
	if !ok {
		return nil, fmt.Errorf("folder not found: %s", resource)
	}
	return folder, nil
}

func (f fakeResourceManagerFoldersClient) GetIAMPolicy(ctx context.Context, resource string) (*iampb.Policy, error) {
	_ = ctx
	if policy, ok := f.policies[resource]; ok {
		return policy, nil
	}
	return nil, fmt.Errorf("policy not found: %s", resource)
}

func (f fakeResourceManagerFoldersClient) Close() error { return nil }

type fakeResourceManagerOrganizationsClient struct {
	orgs     map[string]*resourcemanagerpb.Organization
	policies map[string]*iampb.Policy
}

func (f fakeResourceManagerOrganizationsClient) GetOrganization(ctx context.Context, resource string) (*resourcemanagerpb.Organization, error) {
	_ = ctx
	org, ok := f.orgs[resource]
	if !ok {
		return nil, fmt.Errorf("org not found: %s", resource)
	}
	return org, nil
}

func (f fakeResourceManagerOrganizationsClient) GetIAMPolicy(ctx context.Context, resource string) (*iampb.Policy, error) {
	_ = ctx
	if policy, ok := f.policies[resource]; ok {
		return policy, nil
	}
	return nil, fmt.Errorf("policy not found: %s", resource)
}

func (f fakeResourceManagerOrganizationsClient) Close() error { return nil }

func TestFetchGCPProjectLineageWithClients(t *testing.T) {
	lineage, err := fetchGCPProjectLineageWithClients(
		context.Background(),
		"proj-a",
		fakeResourceManagerProjectsClient{
			projects: []*resourcemanagerpb.Project{{
				Name:        "projects/123456789",
				ProjectId:   "proj-a",
				DisplayName: "Project A",
				Parent:      "folders/456",
			}},
		},
		fakeResourceManagerFoldersClient{
			folders: map[string]*resourcemanagerpb.Folder{
				"folders/456": {Name: "folders/456", Parent: "folders/123", DisplayName: "Engineering"},
				"folders/123": {Name: "folders/123", Parent: "organizations/789", DisplayName: "Platform"},
			},
		},
		fakeResourceManagerOrganizationsClient{
			orgs: map[string]*resourcemanagerpb.Organization{
				"organizations/789": {Name: "organizations/789", DisplayName: "example.com"},
			},
		},
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if lineage.Project == nil || lineage.Project.GetProjectId() != "proj-a" {
		t.Fatalf("unexpected project lineage: %#v", lineage)
	}
	if got := len(lineage.Folders); got != 2 {
		t.Fatalf("expected 2 folders, got %d", got)
	}
	if lineage.Folders[0].GetName() != "folders/123" || lineage.Folders[1].GetName() != "folders/456" {
		t.Fatalf("expected root-to-leaf folder order, got %#v", lineage.Folders)
	}
	if lineage.Organization == nil || lineage.Organization.GetName() != "organizations/789" {
		t.Fatalf("unexpected org lineage: %#v", lineage.Organization)
	}
	if got := lineage.ancestorPath(); len(got) != 3 || got[0] != "organizations/789" || got[2] != "folders/456" {
		t.Fatalf("unexpected ancestor path: %#v", got)
	}
	if got := lineage.folderIDs(); len(got) != 2 || got[0] != "123" || got[1] != "456" {
		t.Fatalf("unexpected folder ids: %#v", got)
	}
}
