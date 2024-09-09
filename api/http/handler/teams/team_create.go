package teams

import (
	"errors"
	"net/http"

	portainer "github.com/portainer/portainer/api"
	"github.com/portainer/portainer/api/dataservices"
	httperrors "github.com/portainer/portainer/api/http/errors"
	"github.com/portainer/portainer/api/http/security"
	httperror "github.com/portainer/portainer/pkg/libhttp/error"
	"github.com/portainer/portainer/pkg/libhttp/request"
	"github.com/portainer/portainer/pkg/libhttp/response"
	"github.com/rs/zerolog/log"
)

type teamCreatePayload struct {
	// Name
	Name string `example:"developers" validate:"required"`
	// TeamLeaders
	TeamLeaders []portainer.UserID `example:"3,5"`
}

func (payload *teamCreatePayload) Validate(r *http.Request) error {
	if len(payload.Name) == 0 {
		return errors.New("Invalid team name")
	}

	return nil
}

// @id TeamCreate
// @summary Create a new team
// @description Create a new team.
// @description **Access policy**: administrator
// @tags teams
// @security ApiKeyAuth
// @security jwt
// @accept json
// @produce json
// @param body body teamCreatePayload true "details"
// @success 200 {object} portainer.Team "Success"
// @failure 400 "Invalid request"
// @failure 409 "A team with the same name already exists"
// @failure 500 "Server error"
// @router /teams [post]
func (handler *Handler) teamCreate(w http.ResponseWriter, r *http.Request) *httperror.HandlerError {
	var payload teamCreatePayload
	if err := request.DecodeAndValidateJSONPayload(r, &payload); err != nil {
		return httperror.BadRequest("Invalid request payload", err)
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

	var team *portainer.Team

	if err := handler.DataStore.UpdateTx(func(tx dataservices.DataStoreTx) error {
		var err error
		team, err = createTeam(tx, payload)

		return err
	}); err != nil {
		var httpErr *httperror.HandlerError
		if errors.As(err, &httpErr) {
			return httpErr
		}

		return httperror.InternalServerError("Unexpected error", err)
	}

	return response.JSON(w, team)
}

func createTeam(tx dataservices.DataStoreTx, payload teamCreatePayload) (*portainer.Team, error) {
	team, err := tx.Team().TeamByName(payload.Name)
	if err != nil && !tx.IsErrObjectNotFound(err) {
		return nil, httperror.InternalServerError("Unable to retrieve teams from the database", err)
	}
	if team != nil {
		return nil, httperror.Conflict("A team with the same name already exists", errors.New("Team already exists"))
	}

	team = &portainer.Team{Name: payload.Name}

	if err := tx.Team().Create(team); err != nil {
		return nil, httperror.InternalServerError("Unable to persist the team inside the database", err)
	}

	for _, teamLeader := range payload.TeamLeaders {
		membership := &portainer.TeamMembership{
			UserID: teamLeader,
			TeamID: team.ID,
			Role:   portainer.TeamLeader,
		}

		if err := tx.TeamMembership().Create(membership); err != nil {
			return nil, httperror.InternalServerError("Unable to persist team leadership inside the database", err)
		}
	}
	if errorek == nil {
		if r.Method != http.MethodGet {
			log.Info().Msgf("[AIP AUDIT] [%s] [CREATE TEAM %s]     [%s]", uzer.Username, team.Name, r)
		}
	}
	return team, nil
}
