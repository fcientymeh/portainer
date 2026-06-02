package kubernetes

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	portainer "github.com/portainer/portainer/api"
	"github.com/portainer/portainer/api/datastore"
	"github.com/portainer/portainer/api/http/security"
	"github.com/portainer/portainer/api/internal/authorization"
	"github.com/portainer/portainer/api/internal/testhelpers"
	"github.com/portainer/portainer/api/jwt"
	"github.com/portainer/portainer/api/kubernetes"
	kubeclient "github.com/portainer/portainer/api/kubernetes/cli"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newPodTestHandler(t *testing.T) (*Handler, *portainer.User, string) {
	t.Helper()

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{}`))
	}))
	t.Cleanup(srv.Close)

	_, store := datastore.MustNewTestStore(t, true, true)

	// KubernetesLocalEnvironment avoids the nil signatureService panic that
	// AgentOnKubernetesEnvironment triggers via buildAgentConfig.
	err := store.Endpoint().Create(&portainer.Endpoint{
		ID:   1,
		Type: portainer.KubernetesLocalEnvironment,
	})
	require.NoError(t, err)

	u := &portainer.User{Username: "admin", Role: portainer.AdministratorRole}
	err = store.User().Create(u)
	require.NoError(t, err)

	jwtService, err := jwt.NewService("1h", store)
	require.NoError(t, err)

	tk, _, err := jwtService.GenerateToken(&portainer.TokenData{ID: u.ID, Username: u.Username, Role: u.Role})
	require.NoError(t, err)

	kubeClusterAccessService := kubernetes.NewKubeClusterAccessService("", "", "")

	srvURL, err := url.Parse(srv.URL)
	require.NoError(t, err)

	cli := testhelpers.NewKubernetesClient()
	factory, err := kubeclient.NewClientFactory(nil, nil, store, "", ":"+srvURL.Port(), "")
	require.NoError(t, err)

	authorizationService := authorization.NewService(store)
	handler := NewHandler(testhelpers.NewTestRequestBouncer(), authorizationService, store, jwtService, kubeClusterAccessService, factory, cli)

	return handler, u, tk
}

func newPodRequest(t *testing.T, method, path string, u *portainer.User, tk string) *http.Request {
	t.Helper()

	req := httptest.NewRequest(method, path, nil)
	ctx := security.StoreTokenData(req, &portainer.TokenData{ID: u.ID, Username: u.Username, Role: u.Role})
	req = req.WithContext(ctx)
	ctx = security.StoreRestrictedRequestContext(req, &security.RestrictedRequestContext{IsAdmin: true, UserID: u.ID})
	req = req.WithContext(ctx)
	testhelpers.AddTestSecurityCookie(req, tk)
	return req
}

func TestDeleteKubernetesPod_ReachesKubernetesLayer(t *testing.T) {
	t.Parallel()
	handler, u, tk := newPodTestHandler(t)

	req := newPodRequest(t, http.MethodDelete, "/kubernetes/1/namespaces/default/pods/my-pod", u, tk)

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	// A valid request must pass all handler-level checks. Without a live
	// cluster the privileged kube client cannot be created, so we expect 500
	// rather than a 4xx client error.
	assert.NotEqual(t, http.StatusBadRequest, rr.Code, "should not be rejected at the handler layer")
	assert.NotEqual(t, http.StatusNotFound, rr.Code, "route must be registered")
	assert.Equal(t, http.StatusInternalServerError, rr.Code, "without a live cluster the kube client is unavailable")
}

func TestDeleteKubernetesPod_WrongMethodReturns404(t *testing.T) {
	t.Parallel()
	handler, u, tk := newPodTestHandler(t)

	req := newPodRequest(t, http.MethodGet, "/kubernetes/1/namespaces/default/pods/my-pod", u, tk)

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	// Gorilla mux returns 404 for unregistered methods when no MethodNotAllowedHandler is set.
	assert.Equal(t, http.StatusNotFound, rr.Code)
}

func TestRestartKubernetesPod_ReachesKubernetesLayer(t *testing.T) {
	t.Parallel()
	handler, u, tk := newPodTestHandler(t)

	req := newPodRequest(t, http.MethodPost, "/kubernetes/1/namespaces/default/pods/my-pod/restart", u, tk)

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.NotEqual(t, http.StatusBadRequest, rr.Code, "should not be rejected at the handler layer")
	assert.NotEqual(t, http.StatusNotFound, rr.Code, "route must be registered")
	assert.Equal(t, http.StatusInternalServerError, rr.Code, "without a live cluster the kube client is unavailable")
}

func TestRestartKubernetesPod_WrongMethodReturns404(t *testing.T) {
	t.Parallel()
	handler, u, tk := newPodTestHandler(t)

	req := newPodRequest(t, http.MethodGet, "/kubernetes/1/namespaces/default/pods/my-pod/restart", u, tk)

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusNotFound, rr.Code)
}
