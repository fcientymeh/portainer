package kubernetes

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	portainer "github.com/portainer/portainer/api"
	"github.com/portainer/portainer/api/datastore"
	models "github.com/portainer/portainer/api/http/models/kubernetes"
	"github.com/portainer/portainer/api/http/security"
	"github.com/portainer/portainer/api/internal/authorization"
	"github.com/portainer/portainer/api/internal/testhelpers"
	"github.com/portainer/portainer/api/jwt"
	"github.com/portainer/portainer/api/kubernetes"
	kubeclient "github.com/portainer/portainer/api/kubernetes/cli"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newServiceAccountTestHandler(t *testing.T) (*Handler, *portainer.User, string) {
	t.Helper()

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{}`))
	}))
	t.Cleanup(srv.Close)

	_, store := datastore.MustNewTestStore(t, true, true)

	err := store.Endpoint().Create(&portainer.Endpoint{
		ID:   1,
		Type: portainer.AgentOnKubernetesEnvironment,
	})
	require.NoError(t, err, "error creating environment")

	u := &portainer.User{Username: "admin", Role: portainer.AdministratorRole}
	err = store.User().Create(u)
	require.NoError(t, err, "error creating a user")

	jwtService, err := jwt.NewService("1h", store)
	require.NoError(t, err, "error initiating jwt service")

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

func newServiceAccountRequest(t *testing.T, method, path string, body []byte, u *portainer.User, tk string) *http.Request {
	t.Helper()

	var req *http.Request
	if body != nil {
		req = httptest.NewRequest(method, path, bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
	} else {
		req = httptest.NewRequest(method, path, nil)
	}

	ctx := security.StoreTokenData(req, &portainer.TokenData{ID: u.ID, Username: u.Username, Role: u.Role})
	req = req.WithContext(ctx)
	ctx = security.StoreRestrictedRequestContext(req, &security.RestrictedRequestContext{IsAdmin: true, UserID: u.ID})
	req = req.WithContext(ctx)
	testhelpers.AddTestSecurityCookie(req, tk)

	return req
}

func TestDeleteKubernetesServiceAccounts_ValidPayload(t *testing.T) {
	t.Parallel()
	handler, u, tk := newServiceAccountTestHandler(t)

	payload := models.K8sServiceAccountDeleteRequests{
		"default": {"sa-1", "sa-2"},
	}
	body, err := json.Marshal(payload)
	require.NoError(t, err)

	req := newServiceAccountRequest(t, http.MethodPost, "/kubernetes/1/service_accounts/delete", body, u, tk)

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.NotEqual(t, http.StatusBadRequest, rr.Code, "should not return bad request for valid payload")
}

func TestDeleteKubernetesServiceAccounts_InvalidPayload(t *testing.T) {
	t.Parallel()
	handler, u, tk := newServiceAccountTestHandler(t)

	payload := models.K8sServiceAccountDeleteRequests{}
	body, err := json.Marshal(payload)
	require.NoError(t, err)

	req := newServiceAccountRequest(t, http.MethodPost, "/kubernetes/1/service_accounts/delete", body, u, tk)

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code, "should return bad request for invalid payload")
	bodyData, err := io.ReadAll(rr.Result().Body)
	require.NoError(t, err)
	assert.NotEmpty(t, string(bodyData), "should have error response body")
}

func TestDeleteKubernetesServiceAccounts_EmptyNamespace(t *testing.T) {
	t.Parallel()
	handler, u, tk := newServiceAccountTestHandler(t)

	payload := models.K8sServiceAccountDeleteRequests{
		"": {"sa-1"},
	}
	body, err := json.Marshal(payload)
	require.NoError(t, err)

	req := newServiceAccountRequest(t, http.MethodPost, "/kubernetes/1/service_accounts/delete", body, u, tk)

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code, "should return bad request for empty namespace")
	bodyData, err := io.ReadAll(rr.Result().Body)
	require.NoError(t, err)
	assert.NotEmpty(t, string(bodyData), "should have error response body")
}
