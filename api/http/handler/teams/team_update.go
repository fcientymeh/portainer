package teams

import (
	"net/http"

	"github.com/rs/zerolog/log"
	"github.com/portainer/portainer/api/http/security"
	httperrors "github.com/portainer/portainer/api/http/errors"
	portainer "github.com/portainer/portainer/api"
	httperror "github.com/portainer/portainer/pkg/libhttp/error"
	"github.com/portainer/portainer/pkg/libhttp/request"
	"github.com/portainer/portainer/pkg/libhttp/response"
)

type teamUpdatePayload struct {
	// Name
	Name string `example:"developers"`
}

func (payload *teamUpdatePayload) Validate(r *http.Request) error {
	return nil
}

// @id TeamUpdate
// @summary Update a team
// @description Update a team.
// @description **Access policy**: administrator
// @tags teams
// @security ApiKeyAuth
// @security jwt
// @accept json
// @produce json
// @param id path int true "Team identifier"
// @param body body teamUpdatePayload true "Team details"
// @success 200 {object} portainer.Team "Success"
// @success 204 "Success"
// @failure 400 "Invalid request"
// @failure 403 "Permission denied"
// @failure 404 "Team not found"
// @failure 500 "Server error"
// @router /teams/{id} [put]
func (handler *Handler) teamUpdate(w http.ResponseWriter, r *http.Request) *httperror.HandlerError {
	teamID, err := request.RetrieveNumericRouteVariableValue(r, "id")
	if err != nil {
		return httperror.BadRequest("Invalid team identifier route variable", err)
	}
	uzer, errorek := security.RetrieveTokenData(r)
//--- AIS: Read-Only user management ---
	teamMemberships, _ := handler.DataStore.TeamMembership().TeamMembershipsByUserID(uzer.ID)
	teamro, err := handler.DataStore.Team().TeamByName("READONLY")
	if err != nil {
    log.Info().Msgf("[AIP AUDIT] [%s] [WARNING! TEAM READONLY DOES NOT EXIST]     [NONE]", uzer.Username)
	}
	for _, membership := range teamMemberships {
		if membership.TeamID == teamro.ID {
				if r.Method != http.MethodGet {
          return &httperror.HandlerError{http.StatusForbidden, "Permission DENIED. READONLY ROLE", httperrors.ErrResourceAccessDenied}
        }				
		}
	}
//------------------------

	var payload teamUpdatePayload
	if err := request.DecodeAndValidateJSONPayload(r, &payload); err != nil {
		return httperror.BadRequest("Invalid request payload", err)
	}

	team, err := handler.DataStore.Team().Read(portainer.TeamID(teamID))
	if handler.DataStore.IsErrObjectNotFound(err) {
		return httperror.NotFound("Unable to find a team with the specified identifier inside the database", err)
	} else if err != nil {
		return httperror.InternalServerError("Unable to find a team with the specified identifier inside the database", err)
	}

	if payload.Name != "" {
		team.Name = payload.Name
	}

	if err := handler.DataStore.Team().Update(team.ID, team); err != nil {
		return httperror.NotFound("Unable to persist team changes inside the database", err)
	}

	if errorek == nil {
		if r.Method != http.MethodGet {
			log.Info().Msgf("[AIP AUDIT] [%s] [CREATE TEAM %s]     [%s]", uzer.Username, team.Name, r)	
		}
	}
	return response.JSON(w, team)
}
