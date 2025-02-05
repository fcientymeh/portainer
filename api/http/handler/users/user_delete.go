package users

import (
	"errors"
	"net/http"

	"github.com/rs/zerolog/log"

	httperrors "github.com/portainer/portainer/api/http/errors"
	portainer "github.com/portainer/portainer/api"
	"github.com/portainer/portainer/api/http/security"
	httperror "github.com/portainer/portainer/pkg/libhttp/error"
	"github.com/portainer/portainer/pkg/libhttp/request"
	"github.com/portainer/portainer/pkg/libhttp/response"
)

// @id UserDelete
// @summary Remove a user
// @description Remove a user.
// @description **Access policy**: administrator
// @tags users
// @security ApiKeyAuth
// @security jwt
// @produce json
// @param id path int true "User identifier"
// @success 204 "Success"
// @failure 400 "Invalid request"
// @failure 403 "Permission denied"
// @failure 404 "User not found"
// @failure 500 "Server error"
// @router /users/{id} [delete]
func (handler *Handler) userDelete(w http.ResponseWriter, r *http.Request) *httperror.HandlerError {
	userID, err := request.RetrieveNumericRouteVariableValue(r, "id")
	if err != nil {
		return httperror.BadRequest("Invalid user identifier route variable", err)
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

	if userID == 1 {
		return httperror.Forbidden("Cannot remove the initial admin account", errors.New("Cannot remove the initial admin account"))
	}

	tokenData, err := security.RetrieveTokenData(r)
	if err != nil {
		return httperror.InternalServerError("Unable to retrieve user authentication token", err)
	}

	if tokenData.ID == portainer.UserID(userID) {
		return httperror.Forbidden("Cannot remove your own user account. Contact another administrator", errAdminCannotRemoveSelf)
	}

	user, err := handler.DataStore.User().Read(portainer.UserID(userID))
	if handler.DataStore.IsErrObjectNotFound(err) {
		return httperror.NotFound("Unable to find a user with the specified identifier inside the database", err)
	} else if err != nil {
		return httperror.InternalServerError("Unable to find a user with the specified identifier inside the database", err)
	}

	if errorek == nil {
		if r.Method != http.MethodGet {
			log.Info().Msgf("[AIP AUDIT] [%s] [DELETE USER %s]     [%s]", uzer.Username, user.Username, r)	
		}
	}
	if user.Role == portainer.AdministratorRole {
		return handler.deleteAdminUser(w, user)
	}

	return handler.deleteUser(w, user)
}

func (handler *Handler) deleteAdminUser(w http.ResponseWriter, user *portainer.User) *httperror.HandlerError {
	if user.Password == "" {
		return handler.deleteUser(w, user)
	}

	users, err := handler.DataStore.User().ReadAll()
	if err != nil {
		return httperror.InternalServerError("Unable to retrieve users from the database", err)
	}

	localAdminCount := 0
	for _, u := range users {
		if u.Role == portainer.AdministratorRole && u.Password != "" {
			localAdminCount++
		}
	}

	if localAdminCount < 2 {
		return httperror.InternalServerError("Cannot remove local administrator user", errCannotRemoveLastLocalAdmin)
	}

	return handler.deleteUser(w, user)
}

func (handler *Handler) deleteUser(w http.ResponseWriter, user *portainer.User) *httperror.HandlerError {
	err := handler.DataStore.User().Delete(user.ID)
	if err != nil {
		return httperror.InternalServerError("Unable to remove user from the database", err)
	}

	err = handler.DataStore.TeamMembership().DeleteTeamMembershipByUserID(user.ID)
	if err != nil {
		return httperror.InternalServerError("Unable to remove user memberships from the database", err)
	}

	// Remove all of the users persisted API keys
	apiKeys, err := handler.apiKeyService.GetAPIKeys(user.ID)
	if err != nil {
		return httperror.InternalServerError("Unable to retrieve user API keys from the database", err)
	}
	for _, k := range apiKeys {
		err = handler.apiKeyService.DeleteAPIKey(k.ID)
		if err != nil {
			return httperror.InternalServerError("Unable to remove user API key from the database", err)
		}
	}

	return response.Empty(w)
}
