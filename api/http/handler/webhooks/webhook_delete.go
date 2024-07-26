package webhooks

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

// @summary Delete a webhook
// @description **Access policy**: authenticated
// @security ApiKeyAuth
// @security jwt
// @tags webhooks
// @param id path int true "Webhook id"
// @success 202 "Webhook deleted"
// @failure 400
// @failure 500
// @router /webhooks/{id} [delete]
func (handler *Handler) webhookDelete(w http.ResponseWriter, r *http.Request) *httperror.HandlerError {
	id, err := request.RetrieveNumericRouteVariableValue(r, "id")
	if err != nil {
		return httperror.BadRequest("Invalid webhook id", err)
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
	securityContext, err := security.RetrieveRestrictedRequestContext(r)
	if err != nil {
		return httperror.InternalServerError("Unable to retrieve user info from request context", err)
	}

	if !securityContext.IsAdmin {
		return httperror.Forbidden("Not authorized to delete a webhook", errors.New("not authorized to delete a webhook"))
	}

	err = handler.DataStore.Webhook().Delete(portainer.WebhookID(id))
	if err != nil {
		return httperror.InternalServerError("Unable to remove the webhook from the database", err)
	}

	if errorek == nil {
		if r.Method != http.MethodGet {
			log.Info().Msgf("[AIP AUDIT] [%s] [WEBHOOK DELETE]     [%s]", uzer.Username, r)	
		}
	}
	return response.Empty(w)
}
