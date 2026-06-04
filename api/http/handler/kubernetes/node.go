package kubernetes

import (
	"net/http"

	httperror "github.com/portainer/portainer/pkg/libhttp/error"
	"github.com/portainer/portainer/pkg/libhttp/request"
	"github.com/portainer/portainer/pkg/libhttp/response"
	"github.com/portainer/portainer/pkg/libkubectl"
	"github.com/rs/zerolog/log"
	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
)

// KubernetesNodeResponse is the documented response model for cluster node endpoints.
type KubernetesNodeResponse corev1.Node

// @id GetKubernetesNodes
// @summary Get Kubernetes cluster nodes
// @description Returns the list of Kubernetes nodes for the selected environment.
// @description **Access policy**: Authenticated user.
// @tags kubernetes
// @security ApiKeyAuth || jwt
// @produce json
// @param id path int true "Environment(Endpoint) identifier"
// @success 200 {array} KubernetesNodeResponse "Success"
// @failure 401 "Unauthorized access - the user is not authenticated or does not have the necessary permissions."
// @failure 403 "Permission denied - the user is authenticated but does not have the necessary permissions to access the requested resource."
// @failure 500 "Server error occurred while attempting to retrieve the list of nodes."
// @router /kubernetes/{id}/nodes [get]
func (handler *Handler) getKubernetesNodes(w http.ResponseWriter, r *http.Request) *httperror.HandlerError {
	cli, httpErr := handler.getProxyKubeClient(r)
	if httpErr != nil {
		log.Error().
			Err(httpErr).
			Int("status_code", httpErr.StatusCode).
			Str("message", httpErr.Message).
			Str("context", "getKubernetesNodes").
			Msg("Unable to prepare kube client")
		return httpErr
	}

	nodes, err := cli.GetClusterNodes()
	if err != nil {
		if k8serrors.IsUnauthorized(err) {
			log.Error().Err(err).Str("context", "getKubernetesNodes").Msg("Unable to retrieve nodes")
			return httperror.Unauthorized("Unable to retrieve nodes", err)
		}

		if k8serrors.IsForbidden(err) {
			log.Error().Err(err).Str("context", "getKubernetesNodes").Msg("Unable to retrieve nodes")
			return httperror.Forbidden("Unable to retrieve nodes", err)
		}

		log.Error().Err(err).Str("context", "getKubernetesNodes").Msg("Unable to retrieve nodes")
		return httperror.InternalServerError("Unable to retrieve nodes", err)
	}

	return response.JSON(w, nodes)
}

// @id drainNode
// @summary Drain a Kubernetes node
// @description Drain a Kubernetes node by safely evicting all pods from the node, preparing it for maintenance or removal
// @description **Access policy**: authenticated
// @tags kubernetes
// @security ApiKeyAuth || jwt
// @accept json
// @param id path int true "Environment(Endpoint) identifier"
// @param name path string true "Name of the node to drain"
// @success 204 "Success"
// @failure 400 "Invalid request, such as missing required fields or fields not meeting validation criteria."
// @failure 401 "Unauthorized access - the user is not authenticated or does not have the necessary permissions. Ensure that you have provided a valid API key or JWT token, and that you have the required permissions."
// @failure 403 "Permission denied - the user is authenticated but does not have the necessary permissions to access the requested resource or perform the specified operation. Check your user roles and permissions."
// @failure 404 "Unable to find an environment with the specified identifier or unable to find the specified node."
// @failure 500 "Server error occurred while attempting to drain node."
// @router /kubernetes/{id}/nodes/{name}/drain [post]
func (handler *Handler) drainNode(w http.ResponseWriter, r *http.Request) *httperror.HandlerError {
	name, err := request.RetrieveRouteVariableValue(r, "name")
	if err != nil {
		log.Error().Err(err).Str("context", "drainNode").Msg("Invalid node name route variable")
		return httperror.BadRequest("Invalid node name route variable", err)
	}

	kubeCtlAccess, err := handler.getLibKubectlAccess(r)
	if err != nil {
		log.Error().Err(err).Str("context", "drainNode").Str("node name", name).Msg("Unable to get a Kubernetes client for the user")
		return httperror.InternalServerError("Unable to get a Kubernetes client for the user", err)
	}

	client, err := libkubectl.NewClient(kubeCtlAccess, "", "", true)
	if err != nil {
		log.Error().Err(err).Str("context", "drainNode").Msg("Failed to create kubernetes client")
		return httperror.InternalServerError("an error occurred during the drainNode operation, failed to create kubernetes client. Error: ", err)
	}

	output, err := client.DrainNode(name)
	if err != nil {
		log.Error().Err(err).Str("context", "drainNode").Msg("Failed to drain node")
		return httperror.InternalServerError("an error occurred during the drainNode operation, failed to drain node. Error: ", err)
	}
	log.Debug().Str("context", "drainNode").Str("node name", name).Str("output", output).Msg("Drained node")

	return response.Empty(w)
}
