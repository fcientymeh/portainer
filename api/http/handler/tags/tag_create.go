package tags

import (
	"errors"
	"net/http"

	portainer "github.com/portainer/portainer/api"
	"github.com/portainer/portainer/api/dataservices"
	httperrors "github.com/portainer/portainer/api/http/errors"
	"github.com/portainer/portainer/api/http/security"
	httperror "github.com/portainer/portainer/pkg/libhttp/error"
	"github.com/portainer/portainer/pkg/libhttp/request"
	"github.com/rs/zerolog/log"
	//"github.com/asaskevich/govalidator"
)

type tagCreatePayload struct {
	Name string `validate:"required" example:"org/acme"`
}

func (payload *tagCreatePayload) Validate(r *http.Request) error {
	if len(payload.Name) == 0 {
		return errors.New("invalid tag name")
	}

	return nil
}

// @id TagCreate
// @summary Create a new tag
// @description Create a new tag.
// @description **Access policy**: administrator
// @tags tags
// @security ApiKeyAuth
// @security jwt
// @accept json
// @produce json
// @param body body tagCreatePayload true "Tag details"
// @success 200 {object} portainer.Tag "Success"
// @failure 409 "This name is already associated to a tag"
// @failure 500 "Server error"
// @router /tags [post]
func (handler *Handler) tagCreate(w http.ResponseWriter, r *http.Request) *httperror.HandlerError {
	var payload tagCreatePayload
	err := request.DecodeAndValidateJSONPayload(r, &payload)
	if err != nil {
		return httperror.BadRequest("Invalid request payload", err)
	}
	//--- AIS: Read-Only user management ---
	uzer, errorek := security.RetrieveTokenData(r)

	teamMemberships, _ := handler.DataStore.TeamMembership().TeamMembershipsByUserID(uzer.ID)
	team, err := handler.DataStore.Team().TeamByName("READONLY")
	if err != nil {
		log.Log().Msgf("[AIP AUDIT] [%s] [WARNING! TEAM READONLY DOES NOT EXIST]     [NONE]", uzer.Username)
	}
	for _, membership := range teamMemberships {
		if membership.TeamID == team.ID {
			if r.Method != http.MethodGet {
				return &httperror.HandlerError{http.StatusForbidden, "Permission DENIED. READONLY ROLE", httperrors.ErrResourceAccessDenied}
			}
		}
	}
	//------------------------
	var tag *portainer.Tag
	err = handler.DataStore.UpdateTx(func(tx dataservices.DataStoreTx) error {
		tag, err = createTag(tx, payload)
		return err
	})
	if errorek == nil {
		if r.Method != http.MethodGet {
			log.Info().Msgf("[AIP AUDIT] [%s] [CREATE TAG %s]     [%s]", uzer.Username, tag.Name, r)
		}
	}
	return txResponse(w, tag, err)
}

func createTag(tx dataservices.DataStoreTx, payload tagCreatePayload) (*portainer.Tag, error) {
	tags, err := tx.Tag().ReadAll()
	if err != nil {
		return nil, httperror.InternalServerError("Unable to retrieve tags from the database", err)
	}

	for _, tag := range tags {
		if tag.Name == payload.Name {
			return nil, httperror.Conflict("This name is already associated to a tag", errors.New("a tag already exists with this name"))
		}
	}

	tag := &portainer.Tag{
		Name:           payload.Name,
		EndpointGroups: map[portainer.EndpointGroupID]bool{},
		Endpoints:      map[portainer.EndpointID]bool{},
	}

	err = tx.Tag().Create(tag)
	if err != nil {
		return nil, httperror.InternalServerError("Unable to persist the tag inside the database", err)
	}

	return tag, nil
}
