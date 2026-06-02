package cli

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kfake "k8s.io/client-go/kubernetes/fake"
)

func TestHumanReadableAccessModes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input []corev1.PersistentVolumeAccessMode
		want  []string
	}{
		{
			name:  "ReadWriteOnce",
			input: []corev1.PersistentVolumeAccessMode{corev1.ReadWriteOnce},
			want:  []string{"RWO"},
		},
		{
			name:  "ReadOnlyMany",
			input: []corev1.PersistentVolumeAccessMode{corev1.ReadOnlyMany},
			want:  []string{"ROX"},
		},
		{
			name:  "ReadWriteMany",
			input: []corev1.PersistentVolumeAccessMode{corev1.ReadWriteMany},
			want:  []string{"RWX"},
		},
		{
			name:  "ReadWriteOncePod",
			input: []corev1.PersistentVolumeAccessMode{corev1.ReadWriteOncePod},
			want:  []string{"RWOP"},
		},
		{
			name:  "unknown mode passes through",
			input: []corev1.PersistentVolumeAccessMode{"SomeUnknownMode"},
			want:  []string{"SomeUnknownMode"},
		},
		{
			name:  "empty slice returns empty slice",
			input: []corev1.PersistentVolumeAccessMode{},
			want:  []string{},
		},
		{
			name:  "multiple modes in order",
			input: []corev1.PersistentVolumeAccessMode{corev1.ReadWriteOnce, corev1.ReadOnlyMany, corev1.ReadWriteMany, corev1.ReadWriteOncePod},
			want:  []string{"RWO", "ROX", "RWX", "RWOP"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := humanReadableAccessModes(tt.input)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestGetPersistentVolumes(t *testing.T) {
	t.Parallel()

	t.Run("empty cluster returns empty slice", func(t *testing.T) {
		t.Parallel()
		k := NewTestKubeClient(kfake.NewClientset())
		pvs, err := k.GetPersistentVolumes()
		require.NoError(t, err)
		assert.Empty(t, pvs)
	})

	t.Run("returns correctly parsed PVs", func(t *testing.T) {
		t.Parallel()
		k := NewTestKubeClient(kfake.NewClientset())

		pv := &corev1.PersistentVolume{
			ObjectMeta: metav1.ObjectMeta{
				Name: "pv-one",
			},
			Spec: corev1.PersistentVolumeSpec{
				StorageClassName: "standard",
				AccessModes:      []corev1.PersistentVolumeAccessMode{corev1.ReadWriteOnce},
			},
			Status: corev1.PersistentVolumeStatus{
				Phase: corev1.VolumeBound,
			},
		}

		_, err := k.cli.CoreV1().PersistentVolumes().Create(t.Context(), pv, metav1.CreateOptions{})
		require.NoError(t, err)

		pvs, err := k.GetPersistentVolumes()
		require.NoError(t, err)
		require.Len(t, pvs, 1)

		got := pvs[0]
		assert.Equal(t, "pv-one", got.Name)
		assert.Equal(t, "standard", got.StorageClassName)
		assert.Equal(t, corev1.VolumeBound, got.Status)
		assert.Equal(t, []string{"RWO"}, got.AccessModes)
	})
}

func TestDeletePersistentVolumes(t *testing.T) {
	t.Parallel()

	t.Run("successfully deletes specified PVs", func(t *testing.T) {
		t.Parallel()
		k := NewTestKubeClient(kfake.NewClientset())

		for _, name := range []string{"pv-a", "pv-b", "pv-c"} {
			pv := &corev1.PersistentVolume{
				ObjectMeta: metav1.ObjectMeta{Name: name},
			}
			_, err := k.cli.CoreV1().PersistentVolumes().Create(t.Context(), pv, metav1.CreateOptions{})
			require.NoError(t, err)
		}

		err := k.DeletePersistentVolumes([]string{"pv-a", "pv-c"})
		require.NoError(t, err)

		pvs, err := k.GetPersistentVolumes()
		require.NoError(t, err)
		require.Len(t, pvs, 1)
		assert.Equal(t, "pv-b", pvs[0].Name)
	})

	t.Run("returns error for non-existent PV", func(t *testing.T) {
		t.Parallel()
		k := NewTestKubeClient(kfake.NewClientset())

		err := k.DeletePersistentVolumes([]string{"does-not-exist"})
		assert.Error(t, err)
	})
}

func TestUpdatePersistentVolumeReclaimPolicy(t *testing.T) {
	t.Parallel()

	t.Run("successfully patches reclaim policy on existing PV", func(t *testing.T) {
		t.Parallel()
		k := NewTestKubeClient(kfake.NewClientset())

		pv := &corev1.PersistentVolume{
			ObjectMeta: metav1.ObjectMeta{Name: "pv-reclaim"},
			Spec: corev1.PersistentVolumeSpec{
				PersistentVolumeReclaimPolicy: corev1.PersistentVolumeReclaimDelete,
			},
		}
		_, err := k.cli.CoreV1().PersistentVolumes().Create(t.Context(), pv, metav1.CreateOptions{})
		require.NoError(t, err)

		err = k.UpdatePersistentVolumeReclaimPolicy("pv-reclaim", corev1.PersistentVolumeReclaimRetain)
		require.NoError(t, err)

		updated, err := k.GetPersistentVolume("pv-reclaim")
		require.NoError(t, err)
		assert.Equal(t, corev1.PersistentVolumeReclaimRetain, updated.PersistentVolumeReclaimPolicy)
	})
}
