package cli

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	storagev1 "k8s.io/api/storage/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kfake "k8s.io/client-go/kubernetes/fake"
)

func makeStorageClass(name string, allowExpansion bool) *storagev1.StorageClass {
	return &storagev1.StorageClass{
		ObjectMeta:           metav1.ObjectMeta{Name: name},
		Provisioner:          "kubernetes.io/no-provisioner",
		AllowVolumeExpansion: &allowExpansion,
	}
}

func makePVC(namespace, name, scName string) *corev1.PersistentVolumeClaim {
	storageRequest := resource.MustParse("1Gi")
	pvc := &corev1.PersistentVolumeClaim{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Spec: corev1.PersistentVolumeClaimSpec{
			Resources: corev1.VolumeResourceRequirements{
				Requests: corev1.ResourceList{
					corev1.ResourceStorage: storageRequest,
				},
			},
		},
	}
	if scName != "" {
		pvc.Spec.StorageClassName = &scName
	}
	return pvc
}

func TestResizePersistentVolumeClaim(t *testing.T) {
	t.Parallel()

	t.Run("returns error when storage class does not allow expansion", func(t *testing.T) {
		t.Parallel()
		k := NewTestKubeClient(kfake.NewClientset())

		sc := makeStorageClass("no-expand", false)
		_, err := k.cli.StorageV1().StorageClasses().Create(t.Context(), sc, metav1.CreateOptions{})
		require.NoError(t, err)

		pvc := makePVC("default", "pvc-no-expand", "no-expand")
		_, err = k.cli.CoreV1().PersistentVolumeClaims("default").Create(t.Context(), pvc, metav1.CreateOptions{})
		require.NoError(t, err)

		err = k.ResizePersistentVolumeClaim("default", "pvc-no-expand", "2Gi")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "does not allow volume expansion")
	})

	t.Run("returns error for invalid size format", func(t *testing.T) {
		t.Parallel()
		k := NewTestKubeClient(kfake.NewClientset())

		sc := makeStorageClass("expandable", true)
		_, err := k.cli.StorageV1().StorageClasses().Create(t.Context(), sc, metav1.CreateOptions{})
		require.NoError(t, err)

		pvc := makePVC("default", "pvc-badsize", "expandable")
		_, err = k.cli.CoreV1().PersistentVolumeClaims("default").Create(t.Context(), pvc, metav1.CreateOptions{})
		require.NoError(t, err)

		err = k.ResizePersistentVolumeClaim("default", "pvc-badsize", "notasize")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid size format")
	})

	t.Run("success when storage class allows expansion with valid size", func(t *testing.T) {
		t.Parallel()
		k := NewTestKubeClient(kfake.NewClientset())

		sc := makeStorageClass("expandable", true)
		_, err := k.cli.StorageV1().StorageClasses().Create(t.Context(), sc, metav1.CreateOptions{})
		require.NoError(t, err)

		pvc := makePVC("default", "pvc-resize", "expandable")
		_, err = k.cli.CoreV1().PersistentVolumeClaims("default").Create(t.Context(), pvc, metav1.CreateOptions{})
		require.NoError(t, err)

		err = k.ResizePersistentVolumeClaim("default", "pvc-resize", "5Gi")
		require.NoError(t, err)
	})

	t.Run("success when PVC has no storage class", func(t *testing.T) {
		t.Parallel()
		k := NewTestKubeClient(kfake.NewClientset())

		pvc := makePVC("default", "pvc-no-sc", "")
		_, err := k.cli.CoreV1().PersistentVolumeClaims("default").Create(t.Context(), pvc, metav1.CreateOptions{})
		require.NoError(t, err)

		err = k.ResizePersistentVolumeClaim("default", "pvc-no-sc", "10Gi")
		require.NoError(t, err)
	})

	t.Run("returns error for non-existent PVC", func(t *testing.T) {
		t.Parallel()
		k := NewTestKubeClient(kfake.NewClientset())

		err := k.ResizePersistentVolumeClaim("default", "does-not-exist", "2Gi")
		require.Error(t, err)
	})
}

func TestGetPersistentVolumeClaims_EnrichesExpansionFlag(t *testing.T) {
	t.Parallel()

	t.Run("PVC with AllowVolumeExpansion=true SC gets flag true", func(t *testing.T) {
		t.Parallel()
		k := NewTestKubeClient(kfake.NewClientset())

		sc := makeStorageClass("expandable", true)
		_, err := k.cli.StorageV1().StorageClasses().Create(t.Context(), sc, metav1.CreateOptions{})
		require.NoError(t, err)

		pvc := makePVC("default", "pvc-expand", "expandable")
		_, err = k.cli.CoreV1().PersistentVolumeClaims("default").Create(t.Context(), pvc, metav1.CreateOptions{})
		require.NoError(t, err)

		pvcs, err := k.GetPersistentVolumeClaims("default")
		require.NoError(t, err)
		require.Len(t, pvcs, 1)
		assert.True(t, pvcs[0].AllowVolumeExpansion)
	})

	t.Run("PVC with AllowVolumeExpansion=false SC gets flag false", func(t *testing.T) {
		t.Parallel()
		k := NewTestKubeClient(kfake.NewClientset())

		sc := makeStorageClass("not-expandable", false)
		_, err := k.cli.StorageV1().StorageClasses().Create(t.Context(), sc, metav1.CreateOptions{})
		require.NoError(t, err)

		pvc := makePVC("default", "pvc-no-expand", "not-expandable")
		_, err = k.cli.CoreV1().PersistentVolumeClaims("default").Create(t.Context(), pvc, metav1.CreateOptions{})
		require.NoError(t, err)

		pvcs, err := k.GetPersistentVolumeClaims("default")
		require.NoError(t, err)
		require.Len(t, pvcs, 1)
		assert.False(t, pvcs[0].AllowVolumeExpansion)
	})
}
