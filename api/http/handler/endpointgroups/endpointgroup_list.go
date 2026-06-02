package endpointgroups

import (
	"net/http"

	portainer "github.com/portainer/portainer/api"
	"github.com/portainer/portainer/api/dataservices"
	"github.com/portainer/portainer/api/http/security"
	"github.com/portainer/portainer/api/set"
	endpointutils "github.com/portainer/portainer/pkg/endpoints"
	httperror "github.com/portainer/portainer/pkg/libhttp/error"
	"github.com/portainer/portainer/pkg/libhttp/request"
	"github.com/portainer/portainer/pkg/libhttp/response"
)

type endpointGroupTypeInfo struct {
	Docker     int  `json:"Docker"`
	Kubernetes int  `json:"Kubernetes"`
	Podman     int  `json:"Podman"`
	Mixed      bool `json:"Mixed"`
}

type endpointGroupResponse struct {
	portainer.EndpointGroup
	Total    int                   `json:"Total,omitzero"`
	TypeInfo endpointGroupTypeInfo `json:"TypeInfo,omitzero"`
}

// @id EndpointGroupList
// @summary List Environment(Endpoint) groups
// @description List all environment(endpoint) groups based on the current user authorizations. Will
// @description return all environment(endpoint) groups if using an administrator account otherwise it will
// @description only return authorized environment(endpoint) groups.
// @description **Access policy**: restricted
// @tags endpoint_groups
// @security ApiKeyAuth
// @security jwt
// @produce json
// @param size query boolean false "If true, each environment(endpoint) group will include the number of environments(endpoints) associated to it and breakdown by type"
// @success 200 {array} endpointGroupResponse "Environment(Endpoint) group"
// @failure 500 "Server error"
// @router /endpoint_groups [get]
func (handler *Handler) endpointGroupList(w http.ResponseWriter, r *http.Request) *httperror.HandlerError {
	includeSize, err := request.RetrieveBooleanQueryParameter(r, "size", true)
	if err != nil {
		return httperror.BadRequest("Invalid query parameter: size", err)
	}

	var endpoints []portainer.Endpoint
	var endpointGroups []portainer.EndpointGroup
	var handlerErr *httperror.HandlerError
	if err := handler.DataStore.ViewTx(func(tx dataservices.DataStoreTx) error {
		var txErr error
		endpointGroups, txErr = handler.DataStore.EndpointGroup().ReadAll()
		if txErr != nil {
			handlerErr = httperror.InternalServerError("Unable to retrieve environment groups from the database", txErr)
			return handlerErr
		}

		if includeSize {
			endpoints, txErr = tx.Endpoint().Endpoints()
			if txErr != nil {
				handlerErr = httperror.InternalServerError("Unable to retrieve endpoints from the database", txErr)
				return handlerErr
			}
		}

		return nil
	}); err != nil {
		if handlerErr != nil {
			return handlerErr
		}
		return httperror.InternalServerError("Unable to retrieve data from the database", err)
	}

	securityContext, err := security.RetrieveRestrictedRequestContext(r)
	if err != nil {
		return httperror.InternalServerError("Unable to retrieve info from request context", err)
	}

	endpointGroups = security.FilterEndpointGroups(endpointGroups, securityContext)

	if len(endpointGroups) == 0 {
		return response.JSON(w, []portainer.EndpointGroup{})
	}
	endpointGroupSet := set.Set[portainer.EndpointGroupID]{}
	if includeSize {
		for i := range endpointGroups {
			endpointGroupSet[endpointGroups[i].ID] = true
		}
	}

	var endpointGroupCountMap map[portainer.EndpointGroupID]int
	var endpointGroupTypeInfoMap map[portainer.EndpointGroupID]endpointGroupTypeInfo
	if includeSize {
		endpointGroupCountMap = make(map[portainer.EndpointGroupID]int)
		endpointGroupTypeInfoMap = make(map[portainer.EndpointGroupID]endpointGroupTypeInfo)
		for _, endpoint := range endpoints {
			if _, ok := endpointGroupSet[endpoint.GroupID]; !ok {
				continue
			}
			endpointGroupCountMap[endpoint.GroupID]++

			typeInfo := endpointGroupTypeInfoMap[endpoint.GroupID]

			if endpointutils.IsKubernetesEndpoint(&endpoint) {
				typeInfo.Kubernetes++
			} else if endpoint.ContainerEngine == "podman" {
				typeInfo.Podman++
			} else {
				typeInfo.Docker++
			}
			endpointGroupTypeInfoMap[endpoint.GroupID] = typeInfo
		}

		for groupID, typeInfo := range endpointGroupTypeInfoMap {
			var bits int
			if typeInfo.Docker > 0 {
				bits |= 1
			}
			if typeInfo.Kubernetes > 0 {
				bits |= 2
			}
			if typeInfo.Podman > 0 {
				bits |= 4
			}
			typeInfo.Mixed = bits&(bits-1) != 0
			endpointGroupTypeInfoMap[groupID] = typeInfo
		}
	}

	endpointGroupsResponse := make([]endpointGroupResponse, len(endpointGroups))
	for i := range endpointGroups {
		groupID := endpointGroups[i].ID

		endpointGroupsResponse[i] = endpointGroupResponse{
			EndpointGroup: endpointGroups[i],
		}

		if includeSize {
			endpointGroupsResponse[i].Total = endpointGroupCountMap[groupID]
			endpointGroupsResponse[i].TypeInfo = endpointGroupTypeInfoMap[groupID]
		}
	}

	return response.JSON(w, endpointGroupsResponse)
}
