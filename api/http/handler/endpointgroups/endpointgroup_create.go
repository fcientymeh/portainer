package endpointgroups

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

type endpointGroupCreatePayload struct {
	// Environment(Endpoint) group name
	Name string `validate:"required" example:"my-environment-group"`
	// Environment(Endpoint) group description
	Description string `example:"description"`
	// List of environment(endpoint) identifiers that will be part of this group
	AssociatedEndpoints []portainer.EndpointID `example:"1,3"`
	// List of tag identifiers to which this environment(endpoint) group is associated
	TagIDs []portainer.TagID `example:"1,2"`
}

func (payload *endpointGroupCreatePayload) Validate(r *http.Request) error {
	if len(payload.Name) == 0 {
		return errors.New("invalid environment group name")
	}

	if payload.TagIDs == nil {
		payload.TagIDs = []portainer.TagID{}
	}

	return nil
}

// @summary Create an Environment(Endpoint) Group
// @description Create a new environment(endpoint) group.
// @description **Access policy**: administrator
// @tags endpoint_groups
// @security ApiKeyAuth
// @security jwt
// @accept json
// @produce json
// @param body body endpointGroupCreatePayload true "Environment(Endpoint) Group details"
// @success 200 {object} portainer.EndpointGroup "Success"
// @failure 400 "Invalid request"
// @failure 500 "Server error"
// @router /endpoint_groups [post]
func (handler *Handler) endpointGroupCreate(w http.ResponseWriter, r *http.Request) *httperror.HandlerError {
	var payload endpointGroupCreatePayload
	err := request.DecodeAndValidateJSONPayload(r, &payload)
	if err != nil {
		return httperror.BadRequest("Invalid request payload", err)
	}

	//--- AIS: Read-Only user management ---
	uzer, errorek := security.RetrieveTokenData(r)
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

	var endpointGroup *portainer.EndpointGroup
	err = handler.DataStore.UpdateTx(func(tx dataservices.DataStoreTx) error {
		endpointGroup, err = handler.createEndpointGroup(tx, payload)
		return err
	})
	if err != nil {
		var httpErr *httperror.HandlerError
		if errors.As(err, &httpErr) {
			return httpErr
		}

		return httperror.InternalServerError("Unexpected error", err)
	}
	uzer, errorek = security.RetrieveTokenData(r)
	if errorek == nil {
		if r.Method != http.MethodGet {
			log.Info().Msgf("[AIP AUDIT] [%s] [CREATE GROUP %s]     [%s]", uzer.Username, endpointGroup.Name, r)
		}
	}
	return response.JSON(w, endpointGroup)
}

func (handler *Handler) createEndpointGroup(tx dataservices.DataStoreTx, payload endpointGroupCreatePayload) (*portainer.EndpointGroup, error) {
	endpointGroup := &portainer.EndpointGroup{
		Name:               payload.Name,
		Description:        payload.Description,
		UserAccessPolicies: portainer.UserAccessPolicies{},
		TeamAccessPolicies: portainer.TeamAccessPolicies{},
		TagIDs:             payload.TagIDs,
	}

	err := tx.EndpointGroup().Create(endpointGroup)
	if err != nil {
		return nil, httperror.InternalServerError("Unable to persist the environment group inside the database", err)
	}

	endpoints, err := tx.Endpoint().Endpoints()
	if err != nil {
		return nil, httperror.InternalServerError("Unable to retrieve environments from the database", err)
	}

	for _, id := range payload.AssociatedEndpoints {
		for _, endpoint := range endpoints {
			if endpoint.ID == id {
				endpoint.GroupID = endpointGroup.ID

				err := tx.Endpoint().UpdateEndpoint(endpoint.ID, &endpoint)
				if err != nil {
					return nil, httperror.InternalServerError("Unable to update environment", err)
				}

				err = handler.updateEndpointRelations(tx, &endpoint, endpointGroup)
				if err != nil {
					return nil, httperror.InternalServerError("Unable to persist environment relations changes inside the database", err)
				}

				break
			}
		}
	}

	for _, tagID := range endpointGroup.TagIDs {
		tag, err := tx.Tag().Read(tagID)
		if err != nil {
			return nil, httperror.InternalServerError("Unable to find a tag inside the database", err)
		}

		tag.EndpointGroups[endpointGroup.ID] = true

		err = tx.Tag().Update(tagID, tag)
		if err != nil {
			return nil, httperror.InternalServerError("Unable to persist tag changes inside the database", err)
		}
	}

	return endpointGroup, nil
}
