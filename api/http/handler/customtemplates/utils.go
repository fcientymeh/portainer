package customtemplates

import (
	"errors"
	"regexp"

	portainer "github.com/portainer/portainer/api"
	"github.com/portainer/portainer/api/dataservices"
)

func populateGitConfig(tx dataservices.DataStoreTx, template *portainer.CustomTemplate) {
	if template.ArtifactSources == nil || len(template.ArtifactSources.SourceIDs) == 0 {
		return
	}

	src, err := tx.Source().Read(template.ArtifactSources.SourceIDs[0])
	if err != nil || src.GitConfig == nil {
		return
	}

	cfg := *src.GitConfig
	cfg.ReferenceName = template.ArtifactSources.Artifact.ReferenceName
	cfg.ConfigFilePath = template.ArtifactSources.Artifact.ConfigFilePath
	cfg.ConfigHash = template.ArtifactSources.Artifact.ConfigHash

	if cfg.Authentication != nil {
		sanitized := *cfg.Authentication
		sanitized.Password = ""
		cfg.Authentication = &sanitized
	}

	template.GitConfig = &cfg
}

// IsValidNote reports whether note is safe to display. Notes containing <img> tags are rejected.
func IsValidNote(note string) bool {
	if len(note) == 0 {
		return true
	}
	match, _ := regexp.MatchString("<img", note)
	return !match
}

// ValidateVariablesDefinitions returns an error if any variable definition is missing a required field.
func ValidateVariablesDefinitions(variables []portainer.CustomTemplateVariableDefinition) error {
	for _, variable := range variables {
		if variable.Name == "" {
			return errors.New("variable name is required")
		}
		if variable.Label == "" {
			return errors.New("variable label is required")
		}
	}
	return nil
}
