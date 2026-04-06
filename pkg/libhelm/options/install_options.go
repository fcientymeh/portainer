package options

import (
	"time"

	portainer "github.com/portainer/portainer/api"
)

type InstallOptions struct {
	Name      string
	Chart     string
	Version   string
	Namespace string
	Repo      string
	Registry  *portainer.Registry
	Wait      bool
	// Values contains inline Helm values merged with the chart defaults.
	// If both are provided, entries in Values override those from ValuesFile.
	Values map[string]any
	// ValuesFile is a path to a YAML file with Helm values to apply.
	// File values are applied first; Values take precedence on conflicts.
	ValuesFile              string
	HelmAppLabels           map[string]string
	Atomic                  bool
	DryRun                  bool
	Timeout                 time.Duration
	KubernetesClusterAccess *KubernetesClusterAccess
	TakeOwnership           bool
	CreateNamespace         bool

	// GitOps related options
	AutoUpdate *portainer.AutoUpdateSettings

	// StackID is the ID of the Portainer stack associated with this release
	StackID int

	// Optional environment vars to pass when running helm
	Env []string
}
