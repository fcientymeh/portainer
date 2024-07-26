package teammemberships

import (
	"net/http"

	"github.com/rs/zerolog/log"

	portainer "github.com/portainer/portainer/api"
	"github.com/portainer/portainer/api/http/errors"
	httperrors "github.com/portainer/portainer/api/http/errors"
	"github.com/portainer/portainer/api/http/security"
	httperror "github.com/portainer/portainer/pkg/libhttp/error"
	"github.com/portainer/portainer/pkg/libhttp/request"
	"github.com/portainer/portainer/pkg/libhttp/response"
)

// @id TeamMembershipDelete
// @summary Remove a team membership
// @description Remove a team membership. Access is only available to administrators leaders of the associated team.
// @description **Access policy**: administrator
// @tags team_memberships
// @security ApiKeyAuth
// @security jwt
// @param id path int true "TeamMembership identifier"
// @success 204 "Success"
// @failure 400 "Invalid request"
// @failure 403 "Permission denied"
// @failure 404 "TeamMembership not found"
// @failure 500 "Server error"
// @router /team_memberships/{id} [delete]
func (handler *Handler) teamMembershipDelete(w http.ResponseWriter, r *http.Request) *httperror.HandlerError {
	membershipID, err := request.RetrieveNumericRouteVariableValue(r, "id")
	if err != nil {
		return httperror.BadRequest("Invalid membership identifier route variable", err)
	}

	membership, err := handler.DataStore.TeamMembership().Read(portainer.TeamMembershipID(membershipID))
	if handler.DataStore.IsErrObjectNotFound(err) {
		return httperror.NotFound("Unable to find a team membership with the specified identifier inside the database", err)
	} else if err != nil {
		return httperror.InternalServerError("Unable to find a team membership with the specified identifier inside the database", err)
	}
	uzer, errorek := security.RetrieveTokenData(r)
	//--- AIS: Read-Only user management ---
	teamMemberships, _ := handler.DataStore.TeamMembership().TeamMembershipsByUserID(uzer.ID)
	team, err := handler.DataStore.Team().TeamByName("READONLY")
	if err != nil {
		log.Info().Msgf("[AIP AUDIT] [%s] [WARNING! TEAM READONLY DOES NOT EXIST]     [NONE]", uzer.Username)
	}
	for _, membership2 := range teamMemberships {
		if membership2.TeamID == team.ID {
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

	if !security.AuthorizedTeamManagement(membership.TeamID, securityContext) {
		return httperror.Forbidden("Permission denied to delete the membership", errors.ErrResourceAccessDenied)
	}

	err = handler.DataStore.TeamMembership().Delete(portainer.TeamMembershipID(membershipID))
	if err != nil {
		return httperror.InternalServerError("Unable to remove the team membership from the database", err)
	}

	defer handler.updateUserServiceAccounts(membership)

	user, err := handler.DataStore.User().Read(portainer.UserID(membership.UserID))
	team2, err := handler.DataStore.Team().Read(portainer.TeamID(membership.TeamID))
	if errorek == nil {
		if r.Method != http.MethodGet {
			log.Info().Msgf("[AIP AUDIT] [%s] [TEAM MEMBERSHIP REMOVE USER %s FROM %s ]     [%s]", uzer.Username, user.Username, team2.Name, r)
		}
	}
	return response.Empty(w)
}
