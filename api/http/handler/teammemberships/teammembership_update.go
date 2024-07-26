package teammemberships

import (
	"errors"
	"net/http"

	"github.com/rs/zerolog/log"

	portainer "github.com/portainer/portainer/api"
	httperrors "github.com/portainer/portainer/api/http/errors"
	"github.com/portainer/portainer/api/http/security"
	httperror "github.com/portainer/portainer/pkg/libhttp/error"
	"github.com/portainer/portainer/pkg/libhttp/request"
	"github.com/portainer/portainer/pkg/libhttp/response"
)

type teamMembershipUpdatePayload struct {
	// User identifier
	UserID int `validate:"required" example:"1"`
	// Team identifier
	TeamID int `validate:"required" example:"1"`
	// Role for the user inside the team (1 for leader and 2 for regular member)
	Role int `validate:"required" example:"1" enums:"1,2"`
}

func (payload *teamMembershipUpdatePayload) Validate(r *http.Request) error {
	if payload.UserID == 0 {
		return errors.New("Invalid UserID")
	}
	if payload.TeamID == 0 {
		return errors.New("Invalid TeamID")
	}
	if payload.Role != 1 && payload.Role != 2 {
		return errors.New("Invalid role value. Value must be one of: 1 (leader) or 2 (member)")
	}
	return nil
}

// @id TeamMembershipUpdate
// @summary Update a team membership
// @description Update a team membership. Access is only available to administrators or leaders of the associated team.
// @description **Access policy**: administrator or leaders of the associated team
// @tags team_memberships
// @security ApiKeyAuth
// @security jwt
// @accept json
// @produce json
// @param id path int true "Team membership identifier"
// @param body body teamMembershipUpdatePayload true "Team membership details"
// @success 200 {object} portainer.TeamMembership "Success"
// @failure 400 "Invalid request"
// @failure 403 "Permission denied"
// @failure 404 "TeamMembership not found"
// @failure 500 "Server error"
// @router /team_memberships/{id} [put]
func (handler *Handler) teamMembershipUpdate(w http.ResponseWriter, r *http.Request) *httperror.HandlerError {
	membershipID, err := request.RetrieveNumericRouteVariableValue(r, "id")
	if err != nil {
		return httperror.BadRequest("Invalid membership identifier route variable", err)
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

	var payload teamMembershipUpdatePayload
	err = request.DecodeAndValidateJSONPayload(r, &payload)
	if err != nil {
		return httperror.BadRequest("Invalid request payload", err)
	}

	membership, err := handler.DataStore.TeamMembership().Read(portainer.TeamMembershipID(membershipID))
	if handler.DataStore.IsErrObjectNotFound(err) {
		return httperror.NotFound("Unable to find a team membership with the specified identifier inside the database", err)
	} else if err != nil {
		return httperror.InternalServerError("Unable to find a team membership with the specified identifier inside the database", err)
	}

	securityContext, err := security.RetrieveRestrictedRequestContext(r)
	if err != nil {
		return httperror.InternalServerError("Unable to retrieve info from request context", err)
	}

	isLeadingBothTeam := security.AuthorizedTeamManagement(portainer.TeamID(payload.TeamID), securityContext) &&
		security.AuthorizedTeamManagement(membership.TeamID, securityContext)
	if !(securityContext.IsAdmin || isLeadingBothTeam) {
		return httperror.Forbidden("Permission denied to update the membership", httperrors.ErrResourceAccessDenied)
	}

	membership.UserID = portainer.UserID(payload.UserID)
	membership.TeamID = portainer.TeamID(payload.TeamID)
	membership.Role = portainer.MembershipRole(payload.Role)
	if membership.UserID == 1 && membership.TeamID == team.ID {
		log.Info().Msgf("[AIP AUDIT] [%s] [CRITICAL CONFIGURATION ERROR!]     [First administrator cannot be added to READONLY group. It can block aip portainer management system]", uzer.Username)
		return &httperror.HandlerError{http.StatusForbidden, "Permission DENIED. READONLY ROLE", httperrors.ErrResourceAccessDenied}
	}
	err = handler.DataStore.TeamMembership().Update(membership.ID, membership)
	if err != nil {
		return httperror.InternalServerError("Unable to persist membership changes inside the database", err)
	}

	defer handler.updateUserServiceAccounts(membership)
	user, err := handler.DataStore.User().Read(portainer.UserID(membership.UserID))
	team2, err := handler.DataStore.Team().Read(portainer.TeamID(membership.TeamID))
	if errorek == nil {
		if r.Method != http.MethodGet {
			log.Info().Msgf("[AIP AUDIT] [%s] [TEAM MEMBERSHIP ADD USER %s FROM TEAM %s AS %s ]     [%s]", uzer.Username, user.Username, team2.Name, membership.Role, r)
		}
	}
	return response.JSON(w, membership)
}
