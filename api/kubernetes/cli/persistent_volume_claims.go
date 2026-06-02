package cli

import (
	"context"
	"errors"
	"fmt"

	models "github.com/portainer/portainer/api/http/models/kubernetes"
	"github.com/rs/zerolog/log"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

// GetPersistentVolumeClaims returns all PVCs in the given namespace (or all namespaces if empty).
// For non-admin users, results are filtered to their accessible namespaces.
func (kcl *KubeClient) GetPersistentVolumeClaims(namespace string) ([]models.K8sPersistentVolumeClaim, error) {
	if kcl.GetIsKubeAdmin() {
		return kcl.fetchPersistentVolumeClaims(namespace)
	}

	return kcl.fetchPersistentVolumeClaimsForNonAdmin(namespace)
}

// GetPersistentVolumeClaim returns a single PVC by namespace and name.
func (kcl *KubeClient) GetPersistentVolumeClaim(namespace, name string) (*models.K8sPersistentVolumeClaim, error) {
	if !kcl.GetIsKubeAdmin() {
		allowedNamespaces := kcl.buildNonAdminNamespacesMap()
		if _, ok := allowedNamespaces[namespace]; !ok {
			return nil, fmt.Errorf("access to namespace %s is not authorized: %w", namespace, ErrUnauthorized)
		}
	}

	pvc, err := kcl.cli.CoreV1().PersistentVolumeClaims(namespace).Get(context.Background(), name, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("unable to get persistent volume claim %s/%s. Error: %w", namespace, name, err)
	}

	result := parsePersistentVolumeClaimDetail(pvc)
	return &result, nil
}

// DeletePersistentVolumeClaims deletes the specified PVCs.
func (kcl *KubeClient) DeletePersistentVolumeClaims(reqs models.K8sVolumeDeleteRequests) error {
	for _, req := range reqs {
		log.Debug().
			Str("context", "DeletePersistentVolumeClaims").
			Str("namespace", req.Namespace).
			Str("name", req.Name).
			Msg("Deleting persistent volume claim")

		err := kcl.cli.CoreV1().PersistentVolumeClaims(req.Namespace).Delete(context.Background(), req.Name, metav1.DeleteOptions{})
		if err != nil {
			return fmt.Errorf("unable to delete persistent volume claim %s/%s. Error: %w", req.Namespace, req.Name, err)
		}
	}

	return nil
}

// ResizePersistentVolumeClaim resizes a PVC to the given new size.
// The storage class must have AllowVolumeExpansion set to true.
func (kcl *KubeClient) ResizePersistentVolumeClaim(namespace, name, newSize string) error {
	pvc, err := kcl.cli.CoreV1().PersistentVolumeClaims(namespace).Get(context.Background(), name, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("unable to get persistent volume claim %s/%s. Error: %w", namespace, name, err)
	}

	if pvc.Spec.StorageClassName != nil {
		sc, err := kcl.GetStorageClass(*pvc.Spec.StorageClassName)
		if err != nil {
			return fmt.Errorf("unable to get storage class %s. Error: %w", *pvc.Spec.StorageClassName, err)
		}

		if sc.AllowVolumeExpansion == nil || !*sc.AllowVolumeExpansion {
			return errors.New("storage class " + sc.Name + " does not allow volume expansion")
		}
	}

	_, err = resource.ParseQuantity(newSize)
	if err != nil {
		return fmt.Errorf("invalid size format %q. Error: %w", newSize, err)
	}

	patch := fmt.Sprintf(`{"spec":{"resources":{"requests":{"storage":"%s"}}}}`, newSize)

	_, err = kcl.cli.CoreV1().PersistentVolumeClaims(namespace).Patch(
		context.Background(),
		name,
		types.MergePatchType,
		[]byte(patch),
		metav1.PatchOptions{},
	)
	if err != nil {
		return fmt.Errorf("unable to resize persistent volume claim %s/%s. Error: %w", namespace, name, err)
	}

	return nil
}

func (kcl *KubeClient) fetchPersistentVolumeClaims(namespace string) ([]models.K8sPersistentVolumeClaim, error) {
	pvcList, err := kcl.cli.CoreV1().PersistentVolumeClaims(namespace).List(context.Background(), metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("unable to list persistent volume claims. Error: %w", err)
	}

	storageClasses, err := kcl.GetStorageClasses()
	if err != nil {
		return nil, fmt.Errorf("unable to list storage classes for volume expansion lookup. Error: %w", err)
	}

	scExpansionMap := make(map[string]bool, len(storageClasses))
	for _, sc := range storageClasses {
		if sc.AllowVolumeExpansion != nil {
			scExpansionMap[sc.Name] = *sc.AllowVolumeExpansion
		}
	}

	results := make([]models.K8sPersistentVolumeClaim, 0, len(pvcList.Items))
	for i := range pvcList.Items {
		pvc := parsePersistentVolumeClaimDetail(&pvcList.Items[i])
		if pvc.StorageClass != nil {
			pvc.AllowVolumeExpansion = scExpansionMap[*pvc.StorageClass]
		}
		results = append(results, pvc)
	}

	return results, nil
}

func (kcl *KubeClient) fetchPersistentVolumeClaimsForNonAdmin(namespace string) ([]models.K8sPersistentVolumeClaim, error) {
	pvcs, err := kcl.fetchPersistentVolumeClaims(namespace)
	if err != nil {
		return nil, err
	}

	nonAdminNamespaceSet := kcl.buildNonAdminNamespacesMap()
	results := make([]models.K8sPersistentVolumeClaim, 0)
	for _, pvc := range pvcs {
		if _, ok := nonAdminNamespaceSet[pvc.Namespace]; ok {
			results = append(results, pvc)
		}
	}

	return results, nil
}

// parsePersistentVolumeClaimDetail parses a PVC into the model with access modes and storage request string.
func parsePersistentVolumeClaimDetail(pvc *corev1.PersistentVolumeClaim) models.K8sPersistentVolumeClaim {
	storage := pvc.Spec.Resources.Requests[corev1.ResourceStorage]
	return models.K8sPersistentVolumeClaim{
		ID:                       string(pvc.UID),
		Name:                     pvc.Name,
		Namespace:                pvc.Namespace,
		CreationDate:             pvc.CreationTimestamp.Time,
		Storage:                  storage.Value(),
		StorageRequest:           storage.String(),
		AccessModes:              humanReadableAccessModes(pvc.Spec.AccessModes),
		HumanReadableAccessModes: pvc.Spec.AccessModes,
		VolumeName:               pvc.Spec.VolumeName,
		ResourcesRequests:        &pvc.Spec.Resources.Requests,
		StorageClass:             pvc.Spec.StorageClassName,
		VolumeMode:               pvc.Spec.VolumeMode,
		OwningApplications:       nil,
		Phase:                    pvc.Status.Phase,
		Labels:                   pvc.Labels,
	}
}
