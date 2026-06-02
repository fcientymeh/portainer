package sources

import (
	portainer "github.com/portainer/portainer/api"
	gittypes "github.com/portainer/portainer/api/git/types"
	ce "github.com/portainer/portainer/api/gitops/workflows"
	"github.com/portainer/portainer/api/set"
)

func workflowsBySourceID(workflows []ce.Workflow) map[string][]ce.Workflow {
	byID := make(map[string][]ce.Workflow)
	for _, wf := range workflows {
		if wf.GitConfig != nil {
			id := sourceID(gitSourceKey(wf.GitConfig))
			byID[id] = append(byID[id], wf)
		}
	}
	return byID
}

func buildSource(id, url string, wfs []ce.Workflow) Source {
	statuses := make([]ce.Status, 0, len(wfs))
	var sourceError string
	var lastSync int64
	endpointIDs := make(set.Set[portainer.EndpointID])
	for _, wf := range wfs {
		statuses = append(statuses, wf.Status.Source.Status)
		if sourceError == "" && wf.Status.Source.Status == ce.StatusError {
			sourceError = wf.Status.Source.Error
		}
		lastSync = max(lastSync, wf.LastSyncDate)
		if wf.Target.EndpointID != 0 {
			endpointIDs.Add(wf.Target.EndpointID)
		}
		for _, id := range wf.Target.ResolvedEndpointIDs {
			endpointIDs.Add(id)
		}
	}
	return Source{
		ID:           id,
		Name:         repoName(url),
		Type:         "git",
		URL:          gittypes.SanitizeURL(url),
		Status:       worstCaseStatus(statuses),
		Error:        sourceError,
		UsedBy:       len(wfs),
		Environments: len(endpointIDs),
		LastSync:     lastSync,
	}
}

func redactWorkflowCredentials(wfs []ce.Workflow) []ce.Workflow {
	redacted := make([]ce.Workflow, len(wfs))
	for i, wf := range wfs {
		redacted[i] = wf
		if wf.GitConfig != nil && wf.GitConfig.Authentication != nil {
			cfg := *wf.GitConfig
			auth := *wf.GitConfig.Authentication
			auth.Password = ""
			cfg.Authentication = &auth
			redacted[i].GitConfig = &cfg
		}
	}
	return redacted
}
