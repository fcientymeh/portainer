package cli

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	v1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kfake "k8s.io/client-go/kubernetes/fake"
)

func TestDeletePod(t *testing.T) {
	t.Parallel()

	t.Run("deletes an existing pod", func(t *testing.T) {
		t.Parallel()
		pod := &v1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "my-pod", Namespace: "default"}}
		kcl := &KubeClient{cli: kfake.NewSimpleClientset(pod)}

		err := kcl.DeletePod("default", "my-pod")
		require.NoError(t, err)
	})

	t.Run("returns not-found error for a missing pod", func(t *testing.T) {
		t.Parallel()
		kcl := &KubeClient{cli: kfake.NewSimpleClientset()}

		err := kcl.DeletePod("default", "nonexistent")
		require.Error(t, err)
		assert.True(t, k8serrors.IsNotFound(err), "expected a not-found error, got: %v", err)
	})

	t.Run("deletes only the named pod leaving others intact", func(t *testing.T) {
		t.Parallel()
		podA := &v1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "pod-a", Namespace: "default"}}
		podB := &v1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "pod-b", Namespace: "default"}}
		fakeClient := kfake.NewSimpleClientset(podA, podB)
		kcl := &KubeClient{cli: fakeClient}

		err := kcl.DeletePod("default", "pod-a")
		require.NoError(t, err)

		_, err = fakeClient.CoreV1().Pods("default").Get(t.Context(), "pod-a", metav1.GetOptions{})
		assert.True(t, k8serrors.IsNotFound(err), "pod-a should have been deleted")

		_, err = fakeClient.CoreV1().Pods("default").Get(t.Context(), "pod-b", metav1.GetOptions{})
		require.NoError(t, err, "pod-b should still exist")
	})

	t.Run("returns not-found when pod exists in a different namespace", func(t *testing.T) {
		t.Parallel()
		pod := &v1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "my-pod", Namespace: "other"}}
		kcl := &KubeClient{cli: kfake.NewSimpleClientset(pod)}

		err := kcl.DeletePod("default", "my-pod")
		require.Error(t, err)
		assert.True(t, k8serrors.IsNotFound(err))
	})
}

func Test_waitForPodStatus(t *testing.T) {
	t.Parallel()

	t.Run("successfully errors on cancelled context", func(t *testing.T) {
		k := &KubeClient{
			cli:        kfake.NewSimpleClientset(),
			instanceID: "test",
		}

		podSpec := &v1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "test", Namespace: defaultNamespace},
			Spec: v1.PodSpec{
				Containers: []v1.Container{
					{Name: "test-pod", Image: "containous/whoami"},
				},
			},
		}

		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		err := k.waitForPodStatus(ctx, v1.PodRunning, podSpec)
		if !errors.Is(err, context.Canceled) {
			t.Errorf("waitForPodStatus should throw context cancellation error; err=%s", err)
		}
	})

	t.Run("successfully errors on timeout", func(t *testing.T) {
		k := &KubeClient{
			cli:        kfake.NewSimpleClientset(),
			instanceID: "test",
		}

		podSpec := &v1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "test", Namespace: defaultNamespace},
			Spec: v1.PodSpec{
				Containers: []v1.Container{
					{Name: "test-pod", Image: "containous/whoami"},
				},
			},
		}

		pod, err := k.cli.CoreV1().Pods(defaultNamespace).Create(t.Context(), podSpec, metav1.CreateOptions{})
		if err != nil {
			t.Errorf("failed to create pod; err=%s", err)
		}
		defer func() {
			err := k.cli.CoreV1().Pods(defaultNamespace).Delete(t.Context(), pod.Name, metav1.DeleteOptions{})
			require.NoError(t, err)
		}()

		ctx, cancelFunc := context.WithTimeout(t.Context(), 0*time.Second)
		defer cancelFunc()

		err = k.waitForPodStatus(ctx, v1.PodRunning, podSpec)
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Errorf("waitForPodStatus should throw deadline exceeded error; err=%s", err)
		}
	})

}
