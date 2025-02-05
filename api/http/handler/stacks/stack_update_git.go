package stacks

import (
	"net/http"
	"time"

	"github.com/rs/zerolog/log"

	portainer "github.com/portainer/portainer/api"
	gittypes "github.com/portainer/portainer/api/git/types"
	"github.com/portainer/portainer/api/git/update"
	httperrors "github.com/portainer/portainer/api/http/errors"
	"github.com/portainer/portainer/api/http/security"
	"github.com/portainer/portainer/api/stacks/deployments"
	"github.com/portainer/portainer/api/stacks/stackutils"
	httperror "github.com/portainer/portainer/pkg/libhttp/error"
	"github.com/portainer/portainer/pkg/libhttp/request"
	"github.com/portainer/portainer/pkg/libhttp/response"

	"github.com/pkg/errors"
)

type stackGitUpdatePayload struct {
	AutoUpdate               *portainer.AutoUpdateSettings
	Env                      []portainer.Pair
	Prune                    bool
	RepositoryReferenceName  string
	RepositoryAuthentication bool
	RepositoryUsername       string
	RepositoryPassword       string
	TLSSkipVerify            bool
}

func (payload *stackGitUpdatePayload) Validate(r *http.Request) error {
	return update.ValidateAutoUpdateSettings(payload.AutoUpdate)
}

// @id StackUpdateGit
// @summary Update a stack's Git configs
// @description Update the Git settings in a stack, e.g., RepositoryReferenceName and AutoUpdate
// @description **Access policy**: authenticated
// @tags stacks
// @security ApiKeyAuth
// @security jwt
// @accept json
// @produce json
// @param id path int true "Stack identifier"
// @param endpointId query int false "Stacks created before version 1.18.0 might not have an associated environment(endpoint) identifier. Use this optional parameter to set the environment(endpoint) identifier used by the stack."
// @param body body stackGitUpdatePayload true "Git configs for pull and redeploy a stack"
// @success 200 {object} portainer.Stack "Success"
// @failure 400 "Invalid request"
// @failure 403 "Permission denied"
// @failure 404 "Not found"
// @failure 500 "Server error"
// @router /stacks/{id}/git [post]
func (handler *Handler) stackUpdateGit(w http.ResponseWriter, r *http.Request) *httperror.HandlerError {
	stackID, err := request.RetrieveNumericRouteVariableValue(r, "id")
	if err != nil {
		return httperror.BadRequest("Invalid stack identifier route variable", err)
	}

	var payload stackGitUpdatePayload
	if err := request.DecodeAndValidateJSONPayload(r, &payload); err != nil {
		return httperror.BadRequest("Invalid request payload", err)
	}

	stack, err := handler.DataStore.Stack().Read(portainer.StackID(stackID))
	if handler.DataStore.IsErrObjectNotFound(err) {
		return httperror.NotFound("Unable to find a stack with the specified identifier inside the database", err)
	} else if err != nil {
		return httperror.InternalServerError("Unable to find a stack with the specified identifier inside the database", err)
	} else if stack.GitConfig == nil {
		msg := "No Git config in the found stack"
		return httperror.InternalServerError(msg, errors.New(msg))
	}
	uzer, errorek := security.RetrieveTokenData(r)
	//--- AIS: Read-Only user management ---
	teamMemberships, _ := handler.DataStore.TeamMembership().TeamMembershipsByUserID(uzer.ID)
	team, err := handler.DataStore.Team().TeamByName("READONLY")
	if err != nil {
		log.Info().Msgf("[AIP AUDIT] [%s] [WARNING! TEAM READONLY DOES NOT EXIST]     [NONE]", uzer.Username)
	}
	for _, membership := range teamMemberships {
		if membership.TeamID == team.ID {
			if r.Method != http.MethodGet {
				return &httperror.HandlerError{http.StatusForbidden, "Permission DENIED. READONLY ROLE", httperrors.ErrResourceAccessDenied}
			}
		}
	}
	//------------------------
	// TODO: this is a work-around for stacks created with Portainer version >= 1.17.1
	// The EndpointID property is not available for these stacks, this API environment(endpoint)
	// can use the optional EndpointID query parameter to associate a valid environment(endpoint) identifier to the stack.
	endpointID, err := request.RetrieveNumericQueryParameter(r, "endpointId", true)
	if err != nil {
		return httperror.BadRequest("Invalid query parameter: endpointId", err)
	}
	if endpointID != int(stack.EndpointID) {
		stack.EndpointID = portainer.EndpointID(endpointID)
	}

	endpoint, err := handler.DataStore.Endpoint().Endpoint(stack.EndpointID)
	if handler.DataStore.IsErrObjectNotFound(err) {
		return httperror.NotFound("Unable to find the environment associated to the stack inside the database", err)
	} else if err != nil {
		return httperror.InternalServerError("Unable to find the environment associated to the stack inside the database", err)
	}

	if err := handler.requestBouncer.AuthorizedEndpointOperation(r, endpoint); err != nil {
		return httperror.Forbidden("Permission denied to access environment", err)
	}

	securityContext, err := security.RetrieveRestrictedRequestContext(r)
	if err != nil {
		return httperror.InternalServerError("Unable to retrieve info from request context", err)
	}

	user, err := handler.DataStore.User().Read(securityContext.UserID)
	if err != nil {
		return httperror.BadRequest("Cannot find context user", errors.Wrap(err, "failed to fetch the user"))
	}

	if stack.Type == portainer.DockerSwarmStack || stack.Type == portainer.DockerComposeStack {
		resourceControl, err := handler.DataStore.ResourceControl().ResourceControlByResourceIDAndType(stackutils.ResourceControlID(stack.EndpointID, stack.Name), portainer.StackResourceControl)
		if err != nil {
			return httperror.InternalServerError("Unable to retrieve a resource control associated to the stack", err)
		}

		if access, err := handler.userCanAccessStack(securityContext, endpoint.ID, resourceControl); err != nil {
			return httperror.InternalServerError("Unable to verify user authorizations to validate stack access", err)
		} else if !access {
			return httperror.Forbidden("Access denied to resource", httperrors.ErrResourceAccessDenied)
		}
	}

	if canManage, err := handler.userCanManageStacks(securityContext, endpoint); err != nil {
		return httperror.InternalServerError("Unable to verify user authorizations to validate stack deletion", err)
	} else if !canManage {
		errMsg := "Stack editing is disabled for non-admin users"
		return httperror.Forbidden(errMsg, errors.New(errMsg))
	}

	//stop the autoupdate job if there is any
	if stack.AutoUpdate != nil {
		deployments.StopAutoupdate(stack.ID, stack.AutoUpdate.JobID, handler.Scheduler)
	}

	//update retrieved stack data based on the payload
	stack.GitConfig.ReferenceName = payload.RepositoryReferenceName
	stack.GitConfig.TLSSkipVerify = payload.TLSSkipVerify
	stack.AutoUpdate = payload.AutoUpdate
	stack.Env = payload.Env
	stack.UpdatedBy = user.Username
	stack.UpdateDate = time.Now().Unix()

	if stack.Type == portainer.DockerSwarmStack {
		stack.Option = &portainer.StackOption{Prune: payload.Prune}
	}

	if payload.RepositoryAuthentication {
		password := payload.RepositoryPassword

		// When the existing stack is using the custom username/password and the password is not updated,
		// the stack should keep using the saved username/password
		if password == "" && stack.GitConfig != nil && stack.GitConfig.Authentication != nil {
			password = stack.GitConfig.Authentication.Password
		}

		stack.GitConfig.Authentication = &gittypes.GitAuthentication{
			Username: payload.RepositoryUsername,
			Password: password,
		}

		if _, err := handler.GitService.LatestCommitID(stack.GitConfig.URL, stack.GitConfig.ReferenceName, stack.GitConfig.Authentication.Username, stack.GitConfig.Authentication.Password, stack.GitConfig.TLSSkipVerify); err != nil {
			return httperror.InternalServerError("Unable to fetch git repository", err)
		}
	} else {
		stack.GitConfig.Authentication = nil
	}

	if payload.AutoUpdate != nil && payload.AutoUpdate.Interval != "" {
		if jobID, err := deployments.StartAutoupdate(stack.ID, stack.AutoUpdate.Interval, handler.Scheduler, handler.StackDeployer, handler.DataStore, handler.GitService); err != nil {
			return err
		} else {
			stack.AutoUpdate.JobID = jobID
		}
	}

	// Save the updated stack to DB
	if err := handler.DataStore.Stack().Update(stack.ID, stack); err != nil {
		return httperror.InternalServerError("Unable to persist the stack changes inside the database", err)
	}

	if stack.GitConfig != nil && stack.GitConfig.Authentication != nil && stack.GitConfig.Authentication.Password != "" {
		// sanitize password in the http response to minimise possible security leaks
		stack.GitConfig.Authentication.Password = ""
	}
	if errorek == nil {
		if r.Method != http.MethodGet {
			log.Info().Msgf("[AIP AUDIT] [%s] [UPDATE GIT STACK %s]     [%s]", uzer.Username, stack.Name, r)
		}
	}
	return response.JSON(w, stack)
}
