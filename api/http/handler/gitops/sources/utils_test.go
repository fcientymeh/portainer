package sources

import (
	"testing"

	portainer "github.com/portainer/portainer/api"
	gittypes "github.com/portainer/portainer/api/git/types"
	ce "github.com/portainer/portainer/api/gitops/workflows"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWorkflowsBySourceID(t *testing.T) {
	t.Parallel()

	t.Run("groups workflows with same URL and credentials", func(t *testing.T) {
		t.Parallel()
		cfg := gitCfg("https://github.com/org/repo")
		wfs := []ce.Workflow{{GitConfig: cfg}, {GitConfig: cfg}}
		byID := workflowsBySourceID(wfs)
		assert.Len(t, byID, 1)
		for _, group := range byID {
			assert.Len(t, group, 2)
		}
	})

	t.Run("separates workflows with same URL but different credentials", func(t *testing.T) {
		t.Parallel()
		wfs := []ce.Workflow{
			{GitConfig: &gittypes.RepoConfig{URL: "https://github.com/org/repo",
				Authentication: &gittypes.GitAuthentication{Username: "alice", Password: "pass1"}}},
			{GitConfig: &gittypes.RepoConfig{URL: "https://github.com/org/repo",
				Authentication: &gittypes.GitAuthentication{Username: "bob", Password: "pass2"}}},
		}
		byID := workflowsBySourceID(wfs)
		assert.Len(t, byID, 2)
	})

	t.Run("skips workflows with nil GitConfig", func(t *testing.T) {
		t.Parallel()
		wfs := []ce.Workflow{{}, {GitConfig: gitCfg("https://github.com/org/repo")}}
		byID := workflowsBySourceID(wfs)
		assert.Len(t, byID, 1)
	})
}

func TestBuildSource(t *testing.T) {
	t.Parallel()

	t.Run("status is the worst across all workflows", func(t *testing.T) {
		t.Parallel()
		wfs := []ce.Workflow{
			{Status: ce.WorkflowStatusObject{Source: ce.WorkflowPhaseStatus{Status: ce.StatusHealthy}}},
			{Status: ce.WorkflowStatusObject{Source: ce.WorkflowPhaseStatus{Status: ce.StatusError, Error: "boom"}}},
		}
		s := buildSource("id", "https://github.com/org/repo.git", wfs)
		assert.Equal(t, ce.StatusError, s.Status)
		assert.Equal(t, "boom", s.Error)
	})

	t.Run("usedBy equals the number of workflows", func(t *testing.T) {
		t.Parallel()
		wfs := make([]ce.Workflow, 3)
		s := buildSource("id", "https://github.com/org/repo", wfs)
		assert.Equal(t, 3, s.UsedBy)
	})

	t.Run("environments deduplicates endpoint IDs", func(t *testing.T) {
		t.Parallel()
		wfs := []ce.Workflow{
			{Target: ce.Target{EndpointID: portainer.EndpointID(1)}},
			{Target: ce.Target{EndpointID: portainer.EndpointID(1)}}, // duplicate
			{Target: ce.Target{EndpointID: portainer.EndpointID(2)}},
		}
		s := buildSource("id", "https://github.com/org/repo", wfs)
		assert.Equal(t, 2, s.Environments)
	})

	t.Run("name is extracted from URL", func(t *testing.T) {
		t.Parallel()
		s := buildSource("id", "https://github.com/org/my-app.git", []ce.Workflow{{}})
		assert.Equal(t, "my-app", s.Name)
	})

	t.Run("lastSync is the maximum across all workflows", func(t *testing.T) {
		t.Parallel()
		wfs := []ce.Workflow{
			{LastSyncDate: 100},
			{LastSyncDate: 300},
			{LastSyncDate: 200},
		}
		s := buildSource("id", "https://github.com/org/repo", wfs)
		assert.Equal(t, int64(300), s.LastSync)
	})
}

func TestRedactWorkflowCredentials(t *testing.T) {
	t.Parallel()

	t.Run("clears password and preserves username", func(t *testing.T) {
		t.Parallel()
		wfs := []ce.Workflow{{GitConfig: &gittypes.RepoConfig{
			Authentication: &gittypes.GitAuthentication{Username: "user", Password: "s3cr3t"},
		}}}
		got := redactWorkflowCredentials(wfs)
		require.NotNil(t, got[0].GitConfig.Authentication)
		assert.Equal(t, "user", got[0].GitConfig.Authentication.Username)
		assert.Empty(t, got[0].GitConfig.Authentication.Password)
	})

	t.Run("does not mutate the original slice", func(t *testing.T) {
		t.Parallel()
		wfs := []ce.Workflow{{GitConfig: &gittypes.RepoConfig{
			Authentication: &gittypes.GitAuthentication{Password: "s3cr3t"},
		}}}
		_ = redactWorkflowCredentials(wfs)
		assert.Equal(t, "s3cr3t", wfs[0].GitConfig.Authentication.Password)
	})

	t.Run("nil GitConfig is safe", func(t *testing.T) {
		t.Parallel()
		assert.NotPanics(t, func() { redactWorkflowCredentials([]ce.Workflow{{}}) })
	})

	t.Run("nil Authentication is safe", func(t *testing.T) {
		t.Parallel()
		wfs := []ce.Workflow{{GitConfig: &gittypes.RepoConfig{}}}
		assert.NotPanics(t, func() { redactWorkflowCredentials(wfs) })
	})
}

func TestBuildAutoUpdateInfo(t *testing.T) {
	t.Parallel()

	assert.Nil(t, buildAutoUpdateInfo(nil))
	assert.Nil(t, buildAutoUpdateInfo(&portainer.AutoUpdateSettings{}))

	got := buildAutoUpdateInfo(&portainer.AutoUpdateSettings{Interval: "5m"})
	require.NotNil(t, got)
	assert.Equal(t, "Interval", got.Mechanism)
	assert.Equal(t, "5m", got.FetchInterval)

	got = buildAutoUpdateInfo(&portainer.AutoUpdateSettings{Webhook: "abc123"})
	require.NotNil(t, got)
	assert.Equal(t, "Webhook", got.Mechanism)
	assert.Empty(t, got.FetchInterval)
}

func TestBuildConnectionInfo(t *testing.T) {
	t.Parallel()

	assert.Nil(t, buildConnectionInfo(nil))

	cfg := &gittypes.RepoConfig{
		ReferenceName:  "refs/heads/main",
		ConfigFilePath: "docker-compose.yml",
		TLSSkipVerify:  true,
		Authentication: &gittypes.GitAuthentication{Username: "user"},
	}
	got := buildConnectionInfo(cfg)
	require.NotNil(t, got)
	assert.Equal(t, "refs/heads/main", got.ReferenceName)
	assert.Equal(t, "docker-compose.yml", got.ConfigFilePath)
	assert.True(t, got.TLSSkipVerify)
	assert.True(t, got.Authentication)

	got = buildConnectionInfo(&gittypes.RepoConfig{})
	assert.False(t, got.Authentication)
}
