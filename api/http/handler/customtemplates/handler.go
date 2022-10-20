package customtemplates

import (
	"net/http"
	"sync"

	"github.com/gorilla/mux"
	httperror "github.com/portainer/libhttp/error"
	portainer "github.com/portainer/portainer/api"
	"github.com/portainer/portainer/api/dataservices"
	"github.com/portainer/portainer/api/http/security"
	"github.com/portainer/portainer/api/internal/authorization"
)

// Handler is the HTTP handler used to handle environment(endpoint) group operations.
type Handler struct {
	*mux.Router
	DataStore      dataservices.DataStore
	FileService    portainer.FileService
	GitService     portainer.GitService
	gitFetchMutexs map[portainer.TemplateID]*sync.Mutex
}

// NewHandler creates a handler to manage environment(endpoint) group operations.
func NewHandler(bouncer *security.RequestBouncer, dataStore dataservices.DataStore, fileService portainer.FileService, gitService portainer.GitService) *Handler {
	h := &Handler{
		Router:         mux.NewRouter(),
		DataStore:      dataStore,
		FileService:    fileService,
		GitService:     gitService,
		gitFetchMutexs: make(map[portainer.TemplateID]*sync.Mutex),
	}
	h.Handle("/custom_templates",
		bouncer.AuthenticatedAccess(httperror.LoggerHandler(h.customTemplateCreate))).Methods(http.MethodPost)
	h.Handle("/custom_templates",
		bouncer.AuthenticatedAccess(httperror.LoggerHandler(h.customTemplateList))).Methods(http.MethodGet)
	h.Handle("/custom_templates/{id}",
		bouncer.AuthenticatedAccess(httperror.LoggerHandler(h.customTemplateInspect))).Methods(http.MethodGet)
	h.Handle("/custom_templates/{id}/file",
		bouncer.AuthenticatedAccess(httperror.LoggerHandler(h.customTemplateFile))).Methods(http.MethodGet)
	h.Handle("/custom_templates/{id}",
		bouncer.AuthenticatedAccess(httperror.LoggerHandler(h.customTemplateUpdate))).Methods(http.MethodPut)
	h.Handle("/custom_templates/{id}",
		bouncer.AuthenticatedAccess(httperror.LoggerHandler(h.customTemplateDelete))).Methods(http.MethodDelete)
	h.Handle("/custom_templates/{id}/git_fetch",
		bouncer.AuthenticatedAccess(httperror.LoggerHandler(h.customTemplateGitFetch))).Methods(http.MethodPut)
	return h
}

func userCanEditTemplate(customTemplate *portainer.CustomTemplate, securityContext *security.RestrictedRequestContext) bool {
	return securityContext.IsAdmin || customTemplate.CreatedByUserID == securityContext.UserID
}

func userCanAccessTemplate(customTemplate portainer.CustomTemplate, securityContext *security.RestrictedRequestContext, resourceControl *portainer.ResourceControl) bool {
	if securityContext.IsAdmin || customTemplate.CreatedByUserID == securityContext.UserID {
		return true
	}

	userTeamIDs := make([]portainer.TeamID, 0)
	for _, membership := range securityContext.UserMemberships {
		userTeamIDs = append(userTeamIDs, membership.TeamID)
	}

	if resourceControl != nil && authorization.UserCanAccessResource(securityContext.UserID, userTeamIDs, resourceControl) {
		return true
	}

	return false
}
