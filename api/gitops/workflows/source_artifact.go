package workflows

import (
	"fmt"

	portainer "github.com/portainer/portainer/api"
	"github.com/portainer/portainer/api/dataservices"
	gittypes "github.com/portainer/portainer/api/git/types"
)

// gitSourceStore is the minimal intersection of CE and EE DataStoreTx that these functions need.
type gitSourceStore interface {
	Workflow() dataservices.WorkflowService
	Source() dataservices.SourceService
}

// GitSourceAndArtifactForStack returns the git Source and the Artifact matching stackID
// from the workflow identified by workflowID.
// Source carries the shared fields (URL, auth, TLS); Artifact carries the stack-specific fields (ref, path, hash).
// Returns nil, nil, nil when workflowID is 0 or no matching entry is found.
func GitSourceAndArtifactForStack(tx gitSourceStore, workflowID portainer.WorkflowID, stackID portainer.StackID) (*portainer.Source, *portainer.Artifact, error) {
	if workflowID == 0 {
		return nil, nil, nil
	}

	wf, err := tx.Workflow().Read(workflowID)
	if err != nil {
		return nil, nil, err
	}

	for i, as := range wf.Artifacts {
		if as.Artifact.StackID != stackID {
			continue
		}

		for _, srcID := range as.SourceIDs {
			src, err := tx.Source().Read(srcID)
			if err != nil {
				return nil, nil, err
			}

			if src.Type == portainer.SourceTypeGit {
				return src, &wf.Artifacts[i].Artifact, nil
			}
		}
	}

	return nil, nil, nil
}

// GitSourceAndArtifactForEdgeStack returns the git Source and the Artifact matching edgeStackID.
// Returns nil, nil, nil when workflowID is 0 or no matching entry is found.
func GitSourceAndArtifactForEdgeStack(tx gitSourceStore, workflowID portainer.WorkflowID, edgeStackID portainer.EdgeStackID) (*portainer.Source, *portainer.Artifact, error) {
	if workflowID == 0 {
		return nil, nil, nil
	}

	wf, err := tx.Workflow().Read(workflowID)
	if err != nil {
		return nil, nil, err
	}

	for i, as := range wf.Artifacts {
		if as.Artifact.EdgeStackID != edgeStackID {
			continue
		}

		for _, srcID := range as.SourceIDs {
			src, err := tx.Source().Read(srcID)
			if err != nil {
				return nil, nil, err
			}

			if src.Type == portainer.SourceTypeGit {
				return src, &wf.Artifacts[i].Artifact, nil
			}
		}
	}

	return nil, nil, nil
}

// MergeSourceAndArtifact builds a RepoConfig by combining shared fields from src (URL, auth, TLS)
// with stack-specific fields from artifact (ref, path, hash).
func MergeSourceAndArtifact(src *portainer.Source, artifact *portainer.Artifact) *gittypes.RepoConfig {
	if src == nil || src.GitConfig == nil {
		return nil
	}

	cfg := &gittypes.RepoConfig{
		URL:            src.GitConfig.URL,
		Authentication: src.GitConfig.Authentication,
		TLSSkipVerify:  src.GitConfig.TLSSkipVerify,
	}

	if artifact != nil {
		cfg.ReferenceName = artifact.ReferenceName
		cfg.ConfigFilePath = artifact.ConfigFilePath
		cfg.ConfigHash = artifact.ConfigHash
	}

	return cfg
}

// UpdateArtifactForStack finds the Artifact matching stackID in the workflow and applies fn to it,
// then persists the updated Workflow. A no-op if no matching Artifact is found.
func UpdateArtifactForStack(tx gitSourceStore, workflowID portainer.WorkflowID, stackID portainer.StackID, fn func(*portainer.Artifact)) error {
	wf, err := tx.Workflow().Read(workflowID)
	if err != nil {
		return err
	}

	for i, as := range wf.Artifacts {
		if as.Artifact.StackID == stackID {
			fn(&wf.Artifacts[i].Artifact)

			return tx.Workflow().Update(workflowID, wf)
		}
	}

	return nil
}

// UpdateArtifactForEdgeStack finds the Artifact matching edgeStackID in the workflow and applies fn to it,
// then persists the updated Workflow. A no-op if no matching Artifact is found.
func UpdateArtifactForEdgeStack(tx gitSourceStore, workflowID portainer.WorkflowID, edgeStackID portainer.EdgeStackID, fn func(*portainer.Artifact)) error {
	wf, err := tx.Workflow().Read(workflowID)
	if err != nil {
		return err
	}

	for i, as := range wf.Artifacts {
		if as.Artifact.EdgeStackID == edgeStackID {
			fn(&wf.Artifacts[i].Artifact)

			return tx.Workflow().Update(workflowID, wf)
		}
	}

	return nil
}

// FindOrCreateGitSource returns an existing Source whose URL and authentication match cfg,
// or creates a new one. Only URL, authentication, and TLSSkipVerify are stored on the Source;
// per-stack fields (ReferenceName, ConfigFilePath, ConfigHash) belong in the Artifact.
func FindOrCreateGitSource(tx gitSourceStore, src *portainer.Source) (*portainer.Source, error) {
	src.GitConfig.URL = gittypes.SanitizeURL(src.GitConfig.URL)

	existing, err := tx.Source().ReadAll(func(s portainer.Source) bool {
		return s.Type == portainer.SourceTypeGit &&
			s.GitConfig != nil &&
			s.GitConfig.URL == src.GitConfig.URL &&
			gitAuthMatches(s.GitConfig.Authentication, src.GitConfig.Authentication)
	})
	if err != nil {
		return nil, err
	}

	if len(existing) > 0 {
		return &existing[0], nil
	}

	toCreate := &portainer.Source{
		Name: src.Name,
		Type: portainer.SourceTypeGit,
		GitConfig: &gittypes.RepoConfig{
			URL:            src.GitConfig.URL,
			Authentication: src.GitConfig.Authentication,
			TLSSkipVerify:  src.GitConfig.TLSSkipVerify,
		},
	}

	if err := tx.Source().Create(toCreate); err != nil {
		return nil, err
	}

	return toCreate, nil
}

// SaveWorkflowGitConfig persists URL/auth/TLS on the Source and ref/path/hash on the Artifact
// matched by matchArtifact. When the URL changes, an existing or new Source is located via
// FindOrCreateGitSource and the Workflow's SourceID is updated atomically alongside the Artifact fields.
func SaveWorkflowGitConfig(tx gitSourceStore, workflowID portainer.WorkflowID, matchArtifact func(portainer.Artifact) bool, oldSourceID portainer.SourceID, cfg *gittypes.RepoConfig) error {
	src, err := tx.Source().Read(oldSourceID)
	if err != nil {
		return fmt.Errorf("failed to read source: %w", err)
	}

	if src.GitConfig == nil {
		return fmt.Errorf("source %d has no git configuration", oldSourceID)
	}

	newSourceID := oldSourceID

	if cfg.URL != src.GitConfig.URL {
		newSrc, err := FindOrCreateGitSource(tx, &portainer.Source{
			Name:      gittypes.RepoName(cfg.URL),
			Type:      portainer.SourceTypeGit,
			GitConfig: cfg,
		})
		if err != nil {
			return fmt.Errorf("failed to find or create source: %w", err)
		}

		newSourceID = newSrc.ID
	} else {
		src.GitConfig.Authentication = cfg.Authentication
		src.GitConfig.TLSSkipVerify = cfg.TLSSkipVerify

		if err := tx.Source().Update(src.ID, src); err != nil {
			return fmt.Errorf("failed to update source: %w", err)
		}
	}

	wf, err := tx.Workflow().Read(workflowID)
	if err != nil {
		return fmt.Errorf("failed to read workflow: %w", err)
	}

	for i, as := range wf.Artifacts {
		if !matchArtifact(as.Artifact) {
			continue
		}

		wf.Artifacts[i].Artifact.ReferenceName = cfg.ReferenceName
		wf.Artifacts[i].Artifact.ConfigFilePath = cfg.ConfigFilePath
		wf.Artifacts[i].Artifact.ConfigHash = cfg.ConfigHash

		if newSourceID != oldSourceID {
			for j, sID := range as.SourceIDs {
				if sID == oldSourceID {
					wf.Artifacts[i].SourceIDs[j] = newSourceID
				}
			}
		}

		break
	}

	return tx.Workflow().Update(workflowID, wf)
}

func gitAuthMatches(a, b *gittypes.GitAuthentication) bool {
	if a == nil && b == nil {
		return true
	}

	if a == nil || b == nil {
		return false
	}

	return a.Username == b.Username && a.Password == b.Password && a.GitCredentialID == b.GitCredentialID
}
