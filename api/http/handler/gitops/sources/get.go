package sources

import (
	"net/http"
	"strconv"

	portainer "github.com/portainer/portainer/api"
	"github.com/portainer/portainer/api/dataservices"
	gittypes "github.com/portainer/portainer/api/git/types"
	ce "github.com/portainer/portainer/api/gitops/workflows"
	"github.com/portainer/portainer/api/http/security"
	httperror "github.com/portainer/portainer/pkg/libhttp/error"
	"github.com/portainer/portainer/pkg/libhttp/request"
	"github.com/portainer/portainer/pkg/libhttp/response"
)

type connectionInfo struct {
	ReferenceName  string `json:"referenceName"`
	ConfigFilePath string `json:"configFilePath"`
	TLSSkipVerify  bool   `json:"tlsSkipVerify"`
	Authentication bool   `json:"authentication,omitempty"`
}

type autoUpdateInfo struct {
	Mechanism     string `json:"mechanism,omitempty"`
	FetchInterval string `json:"fetchInterval,omitempty"`
}

// SourceDetail extends Source with connection settings and linked workflows.
type SourceDetail struct {
	Source
	Connection *connectionInfo `json:"connection,omitempty"`
	AutoUpdate *autoUpdateInfo `json:"autoUpdate,omitempty"`
	Workflows  []ce.Workflow   `json:"workflows"`
}

// @id GitOpsSourceGet
// @summary Get a GitOps source by ID
// @description Returns a single GitOps source with its connection settings and linked workflows.
// @description **Access policy**: admin
// @tags gitops
// @security ApiKeyAuth
// @security jwt
// @produce json
// @param id path int true "Source identifier"
// @success 200 {object} SourceDetail
// @failure 400 "Invalid request"
// @failure 403 "Access denied"
// @failure 404 "Source not found"
// @failure 500 "Server error"
// @router /gitops/sources/{id} [get]
func (h *Handler) getSource(w http.ResponseWriter, r *http.Request) *httperror.HandlerError {
	srcID, err := request.RetrieveNumericRouteVariableValue(r, "id")
	if err != nil {
		return httperror.BadRequest("Invalid source identifier route variable", err)
	}

	securityContext, err := security.RetrieveRestrictedRequestContext(r)
	if err != nil {
		return httperror.InternalServerError("Unable to retrieve info from request context", err)
	}

	var src *portainer.Source

	if err := h.dataStore.ViewTx(func(tx dataservices.DataStoreTx) error {
		var err error
		src, err = tx.Source().Read(portainer.SourceID(srcID))
		return err
	}); h.dataStore.IsErrObjectNotFound(err) {
		return httperror.NotFound("Unable to find a source with the specified identifier", err)
	} else if err != nil {
		return httperror.InternalServerError("Unable to retrieve source", err)
	}

	workflows, err := ce.FetchWorkflows(r.Context(), h.dataStore, h.gitService, h.k8sFactory, securityContext, nil)
	if err != nil {
		return httperror.InternalServerError("Unable to retrieve workflows", err)
	}

	byID := workflowsBySourceID(workflows)

	var wfs []ce.Workflow
	if src.GitConfig != nil {
		wfs = byID[sourceID(gitSourceKey(src.GitConfig))]
	}

	var autoUpdate *portainer.AutoUpdateSettings
	if len(wfs) > 0 {
		autoUpdate = wfs[0].AutoUpdate
	}

	id := strconv.Itoa(int(src.ID))
	url := ""
	if src.GitConfig != nil {
		url = src.GitConfig.URL
	}

	detail := SourceDetail{
		Source:     buildSource(id, url, wfs),
		Connection: buildConnectionInfo(src.GitConfig),
		AutoUpdate: buildAutoUpdateInfo(autoUpdate),
		Workflows:  redactWorkflowCredentials(wfs),
	}
	return response.JSON(w, detail)
}

func buildConnectionInfo(cfg *gittypes.RepoConfig) *connectionInfo {
	if cfg == nil {
		return nil
	}
	return &connectionInfo{
		ReferenceName:  cfg.ReferenceName,
		ConfigFilePath: cfg.ConfigFilePath,
		TLSSkipVerify:  cfg.TLSSkipVerify,
		Authentication: cfg.Authentication != nil,
	}
}

func buildAutoUpdateInfo(autoUpdate *portainer.AutoUpdateSettings) *autoUpdateInfo {
	if autoUpdate == nil {
		return nil
	}

	switch {
	case autoUpdate.Interval != "":
		return &autoUpdateInfo{
			Mechanism:     "Interval",
			FetchInterval: autoUpdate.Interval,
		}
	case autoUpdate.Webhook != "":
		return &autoUpdateInfo{
			Mechanism: "Webhook",
		}
	default:
		return nil
	}
}
