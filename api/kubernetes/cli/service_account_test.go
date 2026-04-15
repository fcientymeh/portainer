package cli

import (
	"testing"

	portainer "github.com/portainer/portainer/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kfake "k8s.io/client-go/kubernetes/fake"
)

func Test_GetServiceAccount(t *testing.T) {
	t.Parallel()

	t.Run("returns error if non-existent", func(t *testing.T) {
		k := &KubeClient{
			cli:        kfake.NewSimpleClientset(),
			instanceID: "test",
		}
		tokenData := &portainer.TokenData{ID: 1}
		_, err := k.GetPortainerUserServiceAccount(tokenData)
		if err == nil {
			t.Error("GetPortainerUserServiceAccount should fail with service account not found")
		}
	})

	t.Run("succeeds for cluster admin role", func(t *testing.T) {
		k := &KubeClient{
			cli:        kfake.NewSimpleClientset(),
			instanceID: "test",
		}

		tokenData := &portainer.TokenData{
			ID:       1,
			Role:     portainer.AdministratorRole,
			Username: portainerClusterAdminServiceAccountName,
		}
		serviceAccount := &v1.ServiceAccount{
			ObjectMeta: metav1.ObjectMeta{
				Name: tokenData.Username,
			},
		}
		_, err := k.cli.CoreV1().ServiceAccounts(portainerNamespace).Create(t.Context(), serviceAccount, metav1.CreateOptions{})
		if err != nil {
			t.Errorf("failed to create service acount; err=%s", err)
		}
		defer func() {
			err := k.cli.CoreV1().ServiceAccounts(portainerNamespace).Delete(t.Context(), serviceAccount.Name, metav1.DeleteOptions{})
			require.NoError(t, err)
		}()

		sa, err := k.GetPortainerUserServiceAccount(tokenData)
		if err != nil {
			t.Errorf("GetPortainerUserServiceAccount should succeed; err=%s", err)
		}

		want := "portainer-sa-clusteradmin"
		if sa.Name != want {
			t.Errorf("GetServiceAccount should succeed and return correct sa name; got=%s want=%s", sa.Name, want)
		}
	})

	t.Run("succeeds for standard user role", func(t *testing.T) {
		k := &KubeClient{
			cli:        kfake.NewSimpleClientset(),
			instanceID: "test",
		}

		tokenData := &portainer.TokenData{
			ID:   1,
			Role: portainer.StandardUserRole,
		}
		serviceAccountName := UserServiceAccountName(int(tokenData.ID), k.instanceID)
		serviceAccount := &v1.ServiceAccount{
			ObjectMeta: metav1.ObjectMeta{
				Name: serviceAccountName,
			},
		}
		_, err := k.cli.CoreV1().ServiceAccounts(portainerNamespace).Create(t.Context(), serviceAccount, metav1.CreateOptions{})
		if err != nil {
			t.Errorf("failed to create service acount; err=%s", err)
		}
		defer func() {
			err := k.cli.CoreV1().ServiceAccounts(portainerNamespace).Delete(t.Context(), serviceAccount.Name, metav1.DeleteOptions{})
			require.NoError(t, err)
		}()

		sa, err := k.GetPortainerUserServiceAccount(tokenData)
		if err != nil {
			t.Errorf("GetPortainerUserServiceAccount should succeed; err=%s", err)
		}

		want := "portainer-sa-user-test-1"
		if sa.Name != want {
			t.Errorf("GetPortainerUserServiceAccount should succeed and return correct sa name; got=%s want=%s", sa.Name, want)
		}
	})

}

func TestGetServiceAccountDetails(t *testing.T) {
	t.Parallel()
	t.Run("returns service account details", func(t *testing.T) {
		automount := false
		sa := &v1.ServiceAccount{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "my-sa",
				Namespace: "default",
				Labels:    map[string]string{"app": "web"},
			},
			AutomountServiceAccountToken: &automount,
			ImagePullSecrets: []v1.LocalObjectReference{
				{Name: "registry-secret"},
			},
		}
		kcl := &KubeClient{
			cli:        kfake.NewSimpleClientset(sa),
			instanceID: "test",
		}

		result, err := kcl.GetServiceAccount("default", "my-sa")
		require.NoError(t, err)

		assert.Equal(t, "my-sa", result.Name)
		assert.Equal(t, "default", result.Namespace)
		assert.Equal(t, &automount, result.AutomountServiceAccountToken)
		assert.Len(t, result.ImagePullSecrets, 1)
		assert.Equal(t, "registry-secret", result.ImagePullSecrets[0].Name)
		assert.Equal(t, map[string]string{"app": "web"}, result.Labels)
	})

	t.Run("returns error when service account not found", func(t *testing.T) {
		kcl := &KubeClient{
			cli:        kfake.NewSimpleClientset(),
			instanceID: "test",
		}

		_, err := kcl.GetServiceAccount("default", "does-not-exist")
		require.Error(t, err)
	})

	t.Run("marks system namespace accounts as system", func(t *testing.T) {
		sa := &v1.ServiceAccount{
			ObjectMeta: metav1.ObjectMeta{Name: "default", Namespace: "kube-system"},
		}
		ns := &v1.Namespace{
			ObjectMeta: metav1.ObjectMeta{Name: "kube-system"},
		}
		kcl := &KubeClient{
			cli:        kfake.NewSimpleClientset(sa, ns),
			instanceID: "test",
		}

		result, err := kcl.GetServiceAccount("kube-system", "default")
		require.NoError(t, err)
		assert.True(t, result.IsSystem)
	})

	t.Run("returns nil automount when not set", func(t *testing.T) {
		sa := &v1.ServiceAccount{
			ObjectMeta: metav1.ObjectMeta{Name: "my-sa", Namespace: "default"},
		}
		kcl := &KubeClient{
			cli:        kfake.NewSimpleClientset(sa),
			instanceID: "test",
		}

		result, err := kcl.GetServiceAccount("default", "my-sa")
		require.NoError(t, err)
		assert.Nil(t, result.AutomountServiceAccountToken)
	})
}

func TestAddImagePullSecretToServiceAccount(t *testing.T) {
	t.Parallel()
	newKCL := func(sa *v1.ServiceAccount) *KubeClient {
		return &KubeClient{cli: kfake.NewSimpleClientset(sa), instanceID: "test"}
	}

	defaultSA := func(namespace string, refs ...string) *v1.ServiceAccount {
		pullSecrets := make([]v1.LocalObjectReference, len(refs))
		for i, r := range refs {
			pullSecrets[i] = v1.LocalObjectReference{Name: r}
		}
		return &v1.ServiceAccount{
			ObjectMeta:       metav1.ObjectMeta{Name: "default", Namespace: namespace},
			ImagePullSecrets: pullSecrets,
		}
	}

	t.Run("adds entry to SA with empty ImagePullSecrets", func(t *testing.T) {
		kcl := newKCL(defaultSA("ns-a"))
		require.NoError(t, kcl.AddImagePullSecretToServiceAccount("ns-a", "default", "registry-1"))

		sa, err := kcl.cli.CoreV1().ServiceAccounts("ns-a").Get(t.Context(), "default", metav1.GetOptions{})
		require.NoError(t, err)
		require.Len(t, sa.ImagePullSecrets, 1)
		assert.Equal(t, "registry-1", sa.ImagePullSecrets[0].Name)
	})

	t.Run("is idempotent when secret already present", func(t *testing.T) {
		kcl := newKCL(defaultSA("ns-a", "registry-1"))
		require.NoError(t, kcl.AddImagePullSecretToServiceAccount("ns-a", "default", "registry-1"))

		sa, err := kcl.cli.CoreV1().ServiceAccounts("ns-a").Get(t.Context(), "default", metav1.GetOptions{})
		require.NoError(t, err)
		assert.Len(t, sa.ImagePullSecrets, 1)
	})

	t.Run("preserves pre-existing pull secrets", func(t *testing.T) {
		kcl := newKCL(defaultSA("ns-a", "other-1", "other-2"))
		require.NoError(t, kcl.AddImagePullSecretToServiceAccount("ns-a", "default", "registry-3"))

		sa, err := kcl.cli.CoreV1().ServiceAccounts("ns-a").Get(t.Context(), "default", metav1.GetOptions{})
		require.NoError(t, err)
		require.Len(t, sa.ImagePullSecrets, 3)
		assert.Equal(t, "other-1", sa.ImagePullSecrets[0].Name)
		assert.Equal(t, "other-2", sa.ImagePullSecrets[1].Name)
		assert.Equal(t, "registry-3", sa.ImagePullSecrets[2].Name)
	})

	t.Run("returns error when SA does not exist", func(t *testing.T) {
		kcl := &KubeClient{cli: kfake.NewSimpleClientset(), instanceID: "test"}
		err := kcl.AddImagePullSecretToServiceAccount("ns-a", "default", "registry-1")
		require.Error(t, err)
	})

	t.Run("works with non-default service account name", func(t *testing.T) {
		sa := &v1.ServiceAccount{
			ObjectMeta: metav1.ObjectMeta{Name: "custom", Namespace: "ns-a"},
		}
		kcl := newKCL(sa)
		require.NoError(t, kcl.AddImagePullSecretToServiceAccount("ns-a", "custom", "registry-1"))

		got, err := kcl.cli.CoreV1().ServiceAccounts("ns-a").Get(t.Context(), "custom", metav1.GetOptions{})
		require.NoError(t, err)
		require.Len(t, got.ImagePullSecrets, 1)
		assert.Equal(t, "registry-1", got.ImagePullSecrets[0].Name)
	})
}

func TestRemoveImagePullSecretFromServiceAccount(t *testing.T) {
	t.Parallel()
	newKCL := func(sa *v1.ServiceAccount) *KubeClient {
		return &KubeClient{cli: kfake.NewSimpleClientset(sa), instanceID: "test"}
	}

	defaultSA := func(namespace string, refs ...string) *v1.ServiceAccount {
		pullSecrets := make([]v1.LocalObjectReference, len(refs))
		for i, r := range refs {
			pullSecrets[i] = v1.LocalObjectReference{Name: r}
		}
		return &v1.ServiceAccount{
			ObjectMeta:       metav1.ObjectMeta{Name: "default", Namespace: namespace},
			ImagePullSecrets: pullSecrets,
		}
	}

	t.Run("removes target entry from ImagePullSecrets", func(t *testing.T) {
		kcl := newKCL(defaultSA("ns-a", "registry-1"))
		require.NoError(t, kcl.RemoveImagePullSecretFromServiceAccount("ns-a", "default", "registry-1"))

		sa, err := kcl.cli.CoreV1().ServiceAccounts("ns-a").Get(t.Context(), "default", metav1.GetOptions{})
		require.NoError(t, err)
		assert.Empty(t, sa.ImagePullSecrets)
	})

	t.Run("is idempotent when secret not in list", func(t *testing.T) {
		kcl := newKCL(defaultSA("ns-a", "other-secret"))
		require.NoError(t, kcl.RemoveImagePullSecretFromServiceAccount("ns-a", "default", "registry-1"))

		sa, err := kcl.cli.CoreV1().ServiceAccounts("ns-a").Get(t.Context(), "default", metav1.GetOptions{})
		require.NoError(t, err)
		assert.Len(t, sa.ImagePullSecrets, 1)
	})

	t.Run("preserves other pull secrets when removing target", func(t *testing.T) {
		kcl := newKCL(defaultSA("ns-a", "other-1", "registry-2", "other-3"))
		require.NoError(t, kcl.RemoveImagePullSecretFromServiceAccount("ns-a", "default", "registry-2"))

		sa, err := kcl.cli.CoreV1().ServiceAccounts("ns-a").Get(t.Context(), "default", metav1.GetOptions{})
		require.NoError(t, err)
		require.Len(t, sa.ImagePullSecrets, 2)
		assert.Equal(t, "other-1", sa.ImagePullSecrets[0].Name)
		assert.Equal(t, "other-3", sa.ImagePullSecrets[1].Name)
	})

	t.Run("returns nil when SA does not exist", func(t *testing.T) {
		kcl := &KubeClient{cli: kfake.NewSimpleClientset(), instanceID: "test"}
		require.NoError(t, kcl.RemoveImagePullSecretFromServiceAccount("ns-a", "default", "registry-1"))
	})

	t.Run("returns nil when ImagePullSecrets is nil", func(t *testing.T) {
		sa := &v1.ServiceAccount{
			ObjectMeta: metav1.ObjectMeta{Name: "default", Namespace: "ns-a"},
		}
		kcl := newKCL(sa)
		require.NoError(t, kcl.RemoveImagePullSecretFromServiceAccount("ns-a", "default", "registry-1"))
	})

	t.Run("removes all occurrences when target appears more than once", func(t *testing.T) {
		kcl := newKCL(defaultSA("ns-a", "registry-1", "registry-1"))
		require.NoError(t, kcl.RemoveImagePullSecretFromServiceAccount("ns-a", "default", "registry-1"))

		sa, err := kcl.cli.CoreV1().ServiceAccounts("ns-a").Get(t.Context(), "default", metav1.GetOptions{})
		require.NoError(t, err)
		assert.Empty(t, sa.ImagePullSecrets)
	})
}

func TestGetServiceAccount_CreatesAndFetches(t *testing.T) {
	t.Parallel()
	t.Run("returns annotations when set", func(t *testing.T) {
		sa := &v1.ServiceAccount{
			ObjectMeta: metav1.ObjectMeta{
				Name:        "annotated-sa",
				Namespace:   "default",
				Annotations: map[string]string{"example.com/key": "value"},
			},
		}
		kcl := &KubeClient{
			cli:        kfake.NewSimpleClientset(sa),
			instanceID: "test",
		}

		result, err := kcl.GetServiceAccount("default", "annotated-sa")
		require.NoError(t, err)
		assert.Equal(t, map[string]string{"example.com/key": "value"}, result.Annotations)
	})

	t.Run("round-trips UID correctly", func(t *testing.T) {
		sa := &v1.ServiceAccount{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "uid-sa",
				Namespace: "default",
				UID:       "abc-123-def",
			},
		}
		kcl := &KubeClient{
			cli:        kfake.NewSimpleClientset(sa),
			instanceID: "test",
		}

		result, err := kcl.GetServiceAccount("default", "uid-sa")
		require.NoError(t, err)
		assert.Equal(t, "abc-123-def", string(result.UID))
	})

	t.Run("creates service account and fetches it back", func(t *testing.T) {
		kcl := &KubeClient{
			cli:        kfake.NewSimpleClientset(),
			instanceID: "test",
		}

		sa := &v1.ServiceAccount{
			ObjectMeta: metav1.ObjectMeta{Name: "fresh-sa", Namespace: "staging"},
		}
		_, err := kcl.cli.CoreV1().ServiceAccounts("staging").Create(t.Context(), sa, metav1.CreateOptions{})
		require.NoError(t, err)

		result, err := kcl.GetServiceAccount("staging", "fresh-sa")
		require.NoError(t, err)
		assert.Equal(t, "fresh-sa", result.Name)
		assert.Equal(t, "staging", result.Namespace)
	})
}
