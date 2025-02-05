package stacks

import (
	"context"
	"errors"
	"net/http"

	portainer "github.com/portainer/portainer/api"
	httperrors "github.com/portainer/portainer/api/http/errors"
	"github.com/portainer/portainer/api/http/security"
	"github.com/portainer/portainer/api/stacks/deployments"
	"github.com/portainer/portainer/api/stacks/stackutils"
	httperror "github.com/portainer/portainer/pkg/libhttp/error"
	"github.com/portainer/portainer/pkg/libhttp/request"
	"github.com/portainer/portainer/pkg/libhttp/response"
	"github.com/rs/zerolog/log"
)

// @id StackStop
// @summary Stops a stopped Stack
// @description Stops a stopped Stack.
// @description **Access policy**: authenticated
// @tags stacks
// @security ApiKeyAuth
// @security jwt
// @param id path int true "Stack identifier"
// @param endpointId query int true "Environment identifier"
// @success 200 {object} portainer.Stack "Success"
// @failure 400 "Invalid request"
// @failure 403 "Permission denied"
// @failure 404 "Not found"
// @failure 500 "Server error"
// @router /stacks/{id}/stop [post]
func (handler *Handler) stackStop(w http.ResponseWriter, r *http.Request) *httperror.HandlerError {
	stackID, err := request.RetrieveNumericRouteVariableValue(r, "id")
	if err != nil {
		return httperror.BadRequest("Invalid stack identifier route variable", err)
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

	securityContext, err := security.RetrieveRestrictedRequestContext(r)
	if err != nil {
		return httperror.InternalServerError("Unable to retrieve info from request context", err)
	}

	stack, err := handler.DataStore.Stack().Read(portainer.StackID(stackID))
	if handler.DataStore.IsErrObjectNotFound(err) {
		return httperror.NotFound("Unable to find a stack with the specified identifier inside the database", err)
	} else if err != nil {
		return httperror.InternalServerError("Unable to find a stack with the specified identifier inside the database", err)
	}

	if stack.Type == portainer.KubernetesStack {
		return httperror.BadRequest("Stopping a kubernetes stack is not supported", err)
	}

	endpointID, err := request.RetrieveNumericQueryParameter(r, "endpointId", false)
	if err != nil {
		return httperror.BadRequest("Invalid query parameter: endpointId", err)
	}

	endpoint, err := handler.DataStore.Endpoint().Endpoint(portainer.EndpointID(endpointID))
	if handler.DataStore.IsErrObjectNotFound(err) {
		return httperror.NotFound("Unable to find an environment with the specified identifier inside the database", err)
	} else if err != nil {
		return httperror.InternalServerError("Unable to find an environment with the specified identifier inside the database", err)
	}

	err = handler.requestBouncer.AuthorizedEndpointOperation(r, endpoint)
	if err != nil {
		return httperror.Forbidden("Permission denied to access environment", err)
	}

	resourceControl, err := handler.DataStore.ResourceControl().ResourceControlByResourceIDAndType(stackutils.ResourceControlID(stack.EndpointID, stack.Name), portainer.StackResourceControl)
	if err != nil {
		return httperror.InternalServerError("Unable to retrieve a resource control associated to the stack", err)
	}

	access, err := handler.userCanAccessStack(securityContext, endpoint.ID, resourceControl)
	if err != nil {
		return httperror.InternalServerError("Unable to verify user authorizations to validate stack access", err)
	}
	if !access {
		return httperror.Forbidden("Access denied to resource", httperrors.ErrResourceAccessDenied)
	}

	canManage, err := handler.userCanManageStacks(securityContext, endpoint)
	if err != nil {
		return httperror.InternalServerError("Unable to verify user authorizations to validate stack deletion", err)
	}
	if !canManage {
		errMsg := "stack management is disabled for non-admin users"
		return httperror.Forbidden(errMsg, errors.New(errMsg))
	}

	if stack.Status == portainer.StackStatusInactive {
		return httperror.BadRequest("Stack is already inactive", errors.New("Stack is already inactive"))
	}

	// stop scheduler updates of the stack before stopping
	if stack.AutoUpdate != nil && stack.AutoUpdate.JobID != "" {
		deployments.StopAutoupdate(stack.ID, stack.AutoUpdate.JobID, handler.Scheduler)
		stack.AutoUpdate.JobID = ""
	}

	err = handler.stopStack(stack, endpoint)
	if err != nil {
		return httperror.InternalServerError("Unable to stop stack", err)
	}

	stack.Status = portainer.StackStatusInactive
	err = handler.DataStore.Stack().Update(stack.ID, stack)
	if err != nil {
		return httperror.InternalServerError("Unable to update stack status", err)
	}

	if stack.GitConfig != nil && stack.GitConfig.Authentication != nil && stack.GitConfig.Authentication.Password != "" {
		// sanitize password in the http response to minimise possible security leaks
		stack.GitConfig.Authentication.Password = ""
	}
	if errorek == nil {
		if r.Method != http.MethodGet {
			log.Info().Msgf("[AIP AUDIT] [%s] [STOP STACK %s]     [%s]", uzer.Username, stack.Name, r)	
		}
	}
	return response.JSON(w, stack)
}

func (handler *Handler) stopStack(stack *portainer.Stack, endpoint *portainer.Endpoint) error {
	switch stack.Type {
	case portainer.DockerComposeStack:
		stack.Name = handler.ComposeStackManager.NormalizeStackName(stack.Name)

		if stackutils.IsRelativePathStack(stack) {
			return handler.StackDeployer.StopRemoteComposeStack(stack, endpoint)
		}

		return handler.ComposeStackManager.Down(context.TODO(), stack, endpoint)
	case portainer.DockerSwarmStack:
		stack.Name = handler.SwarmStackManager.NormalizeStackName(stack.Name)

		if stackutils.IsRelativePathStack(stack) {
			return handler.StackDeployer.StopRemoteSwarmStack(stack, endpoint)
		}

		return handler.SwarmStackManager.Remove(stack, endpoint)
	}

	return nil
}
