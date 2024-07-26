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

type teamMembershipCreatePayload struct {
	// User identifier
	UserID int `validate:"required" example:"1"`
	// Team identifier
	TeamID int `validate:"required" example:"1"`
	// Role for the user inside the team (1 for leader and 2 for regular member)
	Role int `validate:"required" example:"1" enums:"1,2"`
}

func (payload *teamMembershipCreatePayload) Validate(r *http.Request) error {
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

// @id TeamMembershipCreate
// @summary Create a new team membership
// @description Create a new team memberships. Access is only available to administrators leaders of the associated team.
// @description **Access policy**: administrator
// @tags team_memberships
// @security ApiKeyAuth
// @security jwt
// @accept json
// @produce json
// @param body body teamMembershipCreatePayload true "Team membership details"
// @success 200 {object} portainer.TeamMembership "Success"
// @success 204 "Success"
// @failure 400 "Invalid request"
// @failure 403 "Permission denied to manage memberships"
// @failure 409 "Team membership already registered"
// @failure 500 "Server error"
// @router /team_memberships [post]
func (handler *Handler) teamMembershipCreate(w http.ResponseWriter, r *http.Request) *httperror.HandlerError {
	var payload teamMembershipCreatePayload
	err := request.DecodeAndValidateJSONPayload(r, &payload)
	if err != nil {
		return httperror.BadRequest("Invalid request payload", err)
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

	if !security.AuthorizedTeamManagement(portainer.TeamID(payload.TeamID), securityContext) {
		return httperror.Forbidden("Permission denied to manage team memberships", httperrors.ErrResourceAccessDenied)
	}

	memberships, err := handler.DataStore.TeamMembership().TeamMembershipsByUserID(portainer.UserID(payload.UserID))
	if err != nil {
		return httperror.InternalServerError("Unable to retrieve team memberships from the database", err)
	}

	if len(memberships) > 0 {
		for _, membership := range memberships {
			if membership.UserID == portainer.UserID(payload.UserID) && membership.TeamID == portainer.TeamID(payload.TeamID) {
				return httperror.Conflict("Team membership already registered", errors.New("Team membership already exists for this user and team"))
			}
		}
	}

	membership := &portainer.TeamMembership{
		UserID: portainer.UserID(payload.UserID),
		TeamID: portainer.TeamID(payload.TeamID),
		Role:   portainer.MembershipRole(payload.Role),
	}

	err = handler.DataStore.TeamMembership().Create(membership)
	if err != nil {
		return httperror.InternalServerError("Unable to persist team memberships inside the database", err)
	}

	// defer handler.updateUserServiceAccounts(membership)

	if membership.UserID == 1 && membership.TeamID == team.ID {
		log.Info().Msgf("[AIP AUDIT] [%s] [CRITICAL CONFIGURATION ERROR!]     [First administrator cannot be added to READONLY group. It can block aip portainer management system]", uzer.Username)
		return &httperror.HandlerError{http.StatusForbidden, "Permission DENIED. READONLY ROLE", httperrors.ErrResourceAccessDenied}
	}

	user, err := handler.DataStore.User().Read(portainer.UserID(membership.UserID))
	team2, err := handler.DataStore.Team().Read(portainer.TeamID(membership.TeamID))
	if errorek == nil {
		if r.Method != http.MethodGet {
			log.Info().Msgf("[AIP AUDIT] [%s] [TEAM MEMBERSHIP - ADD USER %s TO TEAM %s AS %s]     [%s]", uzer.Username, user.Username, team2.Name, membership.Role, r)
		}
	}
	return response.JSON(w, membership)
}
