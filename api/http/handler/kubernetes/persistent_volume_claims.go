package kubernetes

import (
	"errors"
	"net/http"

	models "github.com/portainer/portainer/api/http/models/kubernetes"
	kcli "github.com/portainer/portainer/api/kubernetes/cli"
	"github.com/rs/zerolog/log"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"

	httperror "github.com/portainer/portainer/pkg/libhttp/error"
	"github.com/portainer/portainer/pkg/libhttp/request"
	"github.com/portainer/portainer/pkg/libhttp/response"
)

// @id GetAllKubernetesPersistentVolumeClaims
// @summary Get all PersistentVolumeClaims
// @description Get a list of all PersistentVolumeClaims within the given environment. Scoped by namespace for non-admin users.
// @description **Access policy**: Authenticated user.
// @tags kubernetes
// @security ApiKeyAuth || jwt
// @produce json
// @param id path int true "Environment identifier"
// @success 200 {array} models.K8sPersistentVolumeClaim "Success"
// @failure 400 "Invalid request payload."
// @failure 403 "Unauthorized access or operation not allowed."
// @failure 500 "Server error occurred while attempting to retrieve persistent volume claims."
// @router /kubernetes/{id}/persistent_volume_claims [get]
func (handler *Handler) getAllKubernetesPersistentVolumeClaims(w http.ResponseWriter, r *http.Request) *httperror.HandlerError {
	cli, httpErr := handler.prepareKubeClient(r)
	if httpErr != nil {
		log.Error().Err(httpErr).Str("context", "GetAllKubernetesPersistentVolumeClaims").Msg("Unable to get Kubernetes client")
		return httpErr
	}

	pvcs, err := cli.GetPersistentVolumeClaims("")
	if err != nil {
		if k8serrors.IsUnauthorized(err) || k8serrors.IsForbidden(err) {
			return httperror.Forbidden("unauthorized access to persistent volume claims", err)
		}

		log.Error().Err(err).Str("context", "GetAllKubernetesPersistentVolumeClaims").Msg("Failed to retrieve persistent volume claims")
		return httperror.InternalServerError("failed to retrieve persistent volume claims", err)
	}

	return response.JSON(w, pvcs)
}

// @id GetKubernetesPersistentVolumeClaimsInNamespace
// @summary Get PersistentVolumeClaims in a namespace
// @description Get a list of PersistentVolumeClaims in the specified namespace.
// @description **Access policy**: Authenticated user.
// @tags kubernetes
// @security ApiKeyAuth || jwt
// @produce json
// @param id path int true "Environment identifier"
// @param namespace path string true "Namespace name"
// @success 200 {array} models.K8sPersistentVolumeClaim "Success"
// @failure 400 "Invalid request payload."
// @failure 403 "Unauthorized access or operation not allowed."
// @failure 500 "Server error occurred while attempting to retrieve persistent volume claims."
// @router /kubernetes/{id}/namespaces/{namespace}/persistent_volume_claims [get]
func (handler *Handler) getKubernetesPVCsInNamespace(w http.ResponseWriter, r *http.Request) *httperror.HandlerError {
	namespace, err := request.RetrieveRouteVariableValue(r, "namespace")
	if err != nil {
		return httperror.BadRequest("invalid namespace identifier", err)
	}

	cli, httpErr := handler.prepareKubeClient(r)
	if httpErr != nil {
		log.Error().Err(httpErr).Str("context", "GetKubernetesPVCsInNamespace").Msg("Unable to get Kubernetes client")
		return httpErr
	}

	pvcs, err := cli.GetPersistentVolumeClaims(namespace)
	if err != nil {
		if k8serrors.IsUnauthorized(err) || k8serrors.IsForbidden(err) {
			return httperror.Forbidden("unauthorized access to persistent volume claims", err)
		}

		log.Error().Err(err).Str("context", "GetKubernetesPVCsInNamespace").Str("namespace", namespace).Msg("Failed to retrieve persistent volume claims")
		return httperror.InternalServerError("failed to retrieve persistent volume claims", err)
	}

	return response.JSON(w, pvcs)
}

// @id GetKubernetesPersistentVolumeClaim
// @summary Get a specific PersistentVolumeClaim
// @description Get a PersistentVolumeClaim by name within a namespace.
// @description **Access policy**: Authenticated user.
// @tags kubernetes
// @security ApiKeyAuth || jwt
// @produce json
// @param id path int true "Environment identifier"
// @param namespace path string true "Namespace name"
// @param name path string true "PVC name"
// @success 200 {object} models.K8sPersistentVolumeClaim "Success"
// @failure 400 "Invalid request payload."
// @failure 403 "Unauthorized access or operation not allowed."
// @failure 404 "PVC not found."
// @failure 500 "Server error occurred while attempting to retrieve the persistent volume claim."
// @router /kubernetes/{id}/namespaces/{namespace}/persistent_volume_claims/{name} [get]
func (handler *Handler) getKubernetesPersistentVolumeClaim(w http.ResponseWriter, r *http.Request) *httperror.HandlerError {
	namespace, err := request.RetrieveRouteVariableValue(r, "namespace")
	if err != nil {
		return httperror.BadRequest("invalid namespace identifier", err)
	}

	name, err := request.RetrieveRouteVariableValue(r, "name")
	if err != nil {
		return httperror.BadRequest("invalid PVC name", err)
	}

	cli, httpErr := handler.prepareKubeClient(r)
	if httpErr != nil {
		log.Error().Err(httpErr).Str("context", "GetKubernetesPersistentVolumeClaim").Msg("Unable to get Kubernetes client")
		return httpErr
	}

	pvc, err := cli.GetPersistentVolumeClaim(namespace, name)
	if err != nil {
		if k8serrors.IsNotFound(err) {
			return httperror.NotFound("persistent volume claim not found", err)
		}

		if errors.Is(err, kcli.ErrUnauthorized) || k8serrors.IsUnauthorized(err) || k8serrors.IsForbidden(err) {
			return httperror.Forbidden("unauthorized access to the Kubernetes API", err)
		}

		log.Error().Err(err).Str("context", "GetKubernetesPersistentVolumeClaim").Str("namespace", namespace).Str("name", name).Msg("Failed to retrieve persistent volume claim")
		return httperror.InternalServerError("failed to retrieve persistent volume claim", err)
	}

	return response.JSON(w, pvc)
}

// @id DeleteKubernetesPersistentVolumeClaims
// @summary Delete PersistentVolumeClaims
// @description Delete the provided list of PersistentVolumeClaims.
// @description **Access policy**: Authenticated user.
// @tags kubernetes
// @security ApiKeyAuth || jwt
// @accept json
// @produce json
// @param id path int true "Environment identifier"
// @param body body []models.K8sVolumeDeleteRequest true "List of PVCs to delete (namespace + name)"
// @success 204 "Success"
// @failure 400 "Invalid request payload."
// @failure 403 "Unauthorized access or operation not allowed."
// @failure 500 "Server error occurred while attempting to delete persistent volume claims."
// @router /kubernetes/{id}/persistent_volume_claims/delete [post]
func (handler *Handler) deleteKubernetesPersistentVolumeClaims(w http.ResponseWriter, r *http.Request) *httperror.HandlerError {
	var payload models.K8sVolumeDeleteRequests
	err := request.DecodeAndValidateJSONPayload(r, &payload)
	if err != nil {
		return httperror.BadRequest("unable to decode and validate the request payload", err)
	}

	cli, httpErr := handler.getProxyKubeClient(r)
	if httpErr != nil {
		return httpErr
	}

	err = cli.DeletePersistentVolumeClaims(payload)
	if err != nil {
		if k8serrors.IsUnauthorized(err) || k8serrors.IsForbidden(err) {
			return httperror.Forbidden("unauthorized access to the Kubernetes API", err)
		}

		if k8serrors.IsNotFound(err) {
			return httperror.NotFound("unable to find the persistent volume claims to delete", err)
		}

		log.Error().Err(err).Str("context", "DeleteKubernetesPersistentVolumeClaims").Msg("Unable to delete persistent volume claims")
		return httperror.InternalServerError("unable to delete persistent volume claims", err)
	}

	return response.Empty(w)
}

// @id ResizeKubernetesPersistentVolumeClaim
// @summary Resize a PersistentVolumeClaim
// @description Resize a PVC to a new size. The StorageClass must support volume expansion.
// @description **Access policy**: Authenticated user.
// @tags kubernetes
// @security ApiKeyAuth || jwt
// @accept json
// @produce json
// @param id path int true "Environment identifier"
// @param body body models.K8sPVCResizeRequest true "PVC resize request"
// @success 204 "Success"
// @failure 400 "Invalid request payload."
// @failure 403 "Unauthorized access or operation not allowed."
// @failure 500 "Server error occurred while attempting to resize the persistent volume claim."
// @router /kubernetes/{id}/persistent_volume_claims/resize [put]
func (handler *Handler) resizeKubernetesPersistentVolumeClaim(w http.ResponseWriter, r *http.Request) *httperror.HandlerError {
	var payload models.K8sPVCResizeRequest
	err := request.DecodeAndValidateJSONPayload(r, &payload)
	if err != nil {
		return httperror.BadRequest("unable to decode and validate the request payload", err)
	}

	cli, httpErr := handler.getProxyKubeClient(r)
	if httpErr != nil {
		return httpErr
	}

	err = cli.ResizePersistentVolumeClaim(payload.Namespace, payload.Name, payload.NewSize)
	if err != nil {
		if k8serrors.IsUnauthorized(err) || k8serrors.IsForbidden(err) {
			return httperror.Forbidden("unauthorized access to the Kubernetes API", err)
		}

		if k8serrors.IsNotFound(err) {
			return httperror.NotFound("persistent volume claim not found", err)
		}

		log.Error().Err(err).Str("context", "ResizeKubernetesPersistentVolumeClaim").
			Str("namespace", payload.Namespace).Str("name", payload.Name).
			Msg("Unable to resize persistent volume claim")
		return httperror.InternalServerError("unable to resize persistent volume claim", err)
	}

	return response.Empty(w)
}
