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

// @id EndpointGroupDelete
// @summary Remove an environment(endpoint) group
// @description Remove an environment(endpoint) group.
// @description **Access policy**: administrator
// @tags endpoint_groups
// @security ApiKeyAuth
// @security jwt
// @param id path int true "EndpointGroup identifier"
// @success 204 "Success"
// @failure 400 "Invalid request"
// @failure 404 "EndpointGroup not found"
// @failure 500 "Server error"
// @router /endpoint_groups/{id} [delete]
func (handler *Handler) endpointGroupDelete(w http.ResponseWriter, r *http.Request) *httperror.HandlerError {
	endpointGroupID, err := request.RetrieveNumericRouteVariableValue(r, "id")
	if err != nil {
		return httperror.BadRequest("Invalid environment group identifier route variable", err)
	}
	uzer, _ := security.RetrieveTokenData(r)
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
	endpointGroup, err := handler.DataStore.EndpointGroup().Read(portainer.EndpointGroupID(endpointGroupID))
	//------------------------

	if endpointGroupID == 1 {
		return httperror.Forbidden("Unable to remove the default 'Unassigned' group", errors.New("Cannot remove the default environment group"))
	}

	err = handler.DataStore.UpdateTx(func(tx dataservices.DataStoreTx) error {
		return handler.deleteEndpointGroup(tx, portainer.EndpointGroupID(endpointGroupID))
	})
	if err != nil {
		var httpErr *httperror.HandlerError
		if errors.As(err, &httpErr) {
			return httpErr
		}

		return httperror.InternalServerError("Unexpected error", err)
	}
	uzer, errorek := security.RetrieveTokenData(r)
	if errorek == nil {
		log.Info().Msgf("[AIP AUDIT] [%s] [DELETE GROUP %s]     [%s]", uzer.Username, endpointGroup.Name, r)
	}
	return response.Empty(w)
}

func (handler *Handler) deleteEndpointGroup(tx dataservices.DataStoreTx, endpointGroupID portainer.EndpointGroupID) error {
	endpointGroup, err := tx.EndpointGroup().Read(endpointGroupID)
	if tx.IsErrObjectNotFound(err) {
		return httperror.NotFound("Unable to find an environment group with the specified identifier inside the database", err)
	} else if err != nil {
		return httperror.InternalServerError("Unable to find an environment group with the specified identifier inside the database", err)
	}

	err = tx.EndpointGroup().Delete(endpointGroupID)
	if err != nil {
		return httperror.InternalServerError("Unable to remove the environment group from the database", err)
	}

	endpoints, err := tx.Endpoint().Endpoints()
	if err != nil {
		return httperror.InternalServerError("Unable to retrieve environment from the database", err)
	}

	for _, endpoint := range endpoints {
		if endpoint.GroupID == endpointGroupID {
			endpoint.GroupID = portainer.EndpointGroupID(1)
			err = tx.Endpoint().UpdateEndpoint(endpoint.ID, &endpoint)
			if err != nil {
				return httperror.InternalServerError("Unable to update environment", err)
			}

			err = handler.updateEndpointRelations(tx, &endpoint, nil)
			if err != nil {
				return httperror.InternalServerError("Unable to persist environment relations changes inside the database", err)
			}
		}
	}

	for _, tagID := range endpointGroup.TagIDs {
		tag, err := tx.Tag().Read(tagID)
		if tx.IsErrObjectNotFound(err) {
			return httperror.InternalServerError("Unable to find a tag inside the database", err)
		}

		delete(tag.EndpointGroups, endpointGroup.ID)

		err = tx.Tag().Update(tagID, tag)
		if err != nil {
			return httperror.InternalServerError("Unable to persist tag changes inside the database", err)
		}
	}
	return nil
}
