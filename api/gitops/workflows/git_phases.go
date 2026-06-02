package workflows

import (
	"context"
	"fmt"
	"path"
	"slices"

	portainer "github.com/portainer/portainer/api"
	gittypes "github.com/portainer/portainer/api/git/types"
)

// ListRefsFunc lists all git refs for a repository.
type ListRefsFunc func(ctx context.Context) ([]string, error)

// ListFilesFunc lists files in a repository branch filtered by extension.
type ListFilesFunc func(ctx context.Context, exts []string, dirOnly bool) ([]string, error)

// GitEntries represents a git entry which can be either a file or a directory.
type GitEntries struct {
	Name   string
	IsFile bool
}

// ComputeGitPhasesForConfig computes source and artifact phases from a RepoConfig and a GitService.
func ComputeGitPhasesForConfig(ctx context.Context, gitSvc portainer.GitService, cfg *gittypes.RepoConfig) (source, artifact WorkflowPhaseStatus) {
	if gitSvc == nil || cfg == nil {
		return WorkflowPhaseStatus{Status: StatusUnknown}, WorkflowPhaseStatus{Status: StatusUnknown}
	}

	username, password := gitCredentials(cfg)
	return ComputeGitPhases(ctx, cfg.ReferenceName, []GitEntries{{Name: cfg.ConfigFilePath, IsFile: true}},
		func(ctx context.Context) ([]string, error) {
			return gitSvc.ListRefs(ctx, cfg.URL, username, password, false, cfg.TLSSkipVerify)
		},
		func(ctx context.Context, exts []string, dirOnly bool) ([]string, error) {
			return gitSvc.ListFiles(ctx, cfg.URL, cfg.ReferenceName, username, password, dirOnly, false, exts, cfg.TLSSkipVerify)
		},
	)
}

func gitCredentials(cfg *gittypes.RepoConfig) (username, password string) {
	if cfg.Authentication != nil {
		return cfg.Authentication.Username, cfg.Authentication.Password
	}
	return "", ""
}

// ComputeGitPhases checks source (ref reachability) and artifact (config file presence).
// If source fails, artifact is returned as unknown without making a network call.
func ComputeGitPhases(ctx context.Context, referenceName string, configFilePath []GitEntries, listRefs ListRefsFunc, listFiles ListFilesFunc) (source, artifact WorkflowPhaseStatus) {
	source = computeSourcePhase(ctx, referenceName, listRefs)
	if source.Status == StatusError {
		return source, WorkflowPhaseStatus{Status: StatusUnknown}
	}
	return source, computeArtifactPhase(ctx, configFilePath, listFiles)
}

func computeSourcePhase(ctx context.Context, referenceName string, listRefs ListRefsFunc) WorkflowPhaseStatus {
	refs, err := listRefs(ctx)
	if err != nil {
		return WorkflowPhaseStatus{Status: StatusError, Error: err.Error()}
	}
	if referenceName == "" {
		return WorkflowPhaseStatus{Status: StatusHealthy}
	}
	if !slices.Contains(refs, referenceName) {
		return WorkflowPhaseStatus{Status: StatusError, Error: fmt.Sprintf("ref %q not found", referenceName)}
	}
	return WorkflowPhaseStatus{Status: StatusHealthy}
}

func computeArtifactPhase(ctx context.Context, gitEntries []GitEntries, listFiles ListFilesFunc) WorkflowPhaseStatus {
	if len(gitEntries) == 0 {
		return WorkflowPhaseStatus{Status: StatusError, Error: "no config file path specified"}
	}

	var (
		exts        []string
		fileEntries []string
		dirEntries  []string
	)
	for _, gitEntry := range gitEntries {
		if gitEntry.IsFile {
			ext := path.Ext(gitEntry.Name)
			if len(ext) > 0 {
				ext = ext[1:]
				exts = append(exts, ext)
			}

			fileEntries = append(fileEntries, gitEntry.Name)
			continue
		}

		dirEntries = append(dirEntries, gitEntry.Name)
	}

	// Check file entries
	if len(fileEntries) > 0 {
		files, err := listFiles(ctx, exts, false)
		if err != nil {
			return WorkflowPhaseStatus{Status: StatusError, Error: err.Error()}
		}

		for _, fileEntry := range fileEntries {
			if !slices.Contains(files, fileEntry) {
				return WorkflowPhaseStatus{Status: StatusError, Error: fmt.Sprintf("file %q not found", fileEntry)}
			}
		}
	}

	// Check directory entries
	if len(dirEntries) > 0 {
		dirs, err := listFiles(ctx, nil, true)
		if err != nil {
			return WorkflowPhaseStatus{Status: StatusError, Error: err.Error()}
		}

		for _, dirEntry := range dirEntries {
			if !slices.Contains(dirs, dirEntry) {
				return WorkflowPhaseStatus{Status: StatusError, Error: fmt.Sprintf("directory %q not found", dirEntry)}
			}
		}
	}

	return WorkflowPhaseStatus{Status: StatusHealthy}
}
