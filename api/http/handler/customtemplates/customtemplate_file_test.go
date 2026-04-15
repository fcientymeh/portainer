package customtemplates

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
	portainer "github.com/portainer/portainer/api"
	"github.com/portainer/portainer/api/dataservices"
	"github.com/portainer/portainer/api/http/security"
	httperror "github.com/portainer/portainer/pkg/libhttp/error"
	"github.com/segmentio/encoding/json"
	"github.com/stretchr/testify/require"
)

func TestCustomTemplateFile(t *testing.T) {
	t.Parallel()

	handler, ds, fs := newTestHandler(t)

	templateContent := "some template content"
	templateEntrypoint := "entrypoint"

	require.NoError(t, ds.UpdateTx(func(tx dataservices.DataStoreTx) error {
		// template 1
		path, err := fs.StoreCustomTemplateFileFromBytes("1", templateEntrypoint, []byte(templateContent))
		require.NoError(t, err)
		require.NoError(t, tx.CustomTemplate().Create(&portainer.CustomTemplate{ID: 1, EntryPoint: templateEntrypoint, ProjectPath: path}))

		// template 2
		path, err = fs.StoreCustomTemplateFileFromBytes("2", templateEntrypoint, []byte(templateContent))
		require.NoError(t, err)
		require.NoError(t, tx.CustomTemplate().Create(&portainer.CustomTemplate{ID: 2, EntryPoint: templateEntrypoint, ProjectPath: path}))

		require.NoError(t, tx.ResourceControl().Create(&portainer.ResourceControl{ID: 1, ResourceID: "2", Type: portainer.CustomTemplateResourceControl,
			UserAccesses: []portainer.UserResourceAccess{{UserID: 2}},
			TeamAccesses: []portainer.TeamResourceAccess{{TeamID: 1}},
		}))
		return nil
	}))

	test := func(templateID string, restrictedContext *security.RestrictedRequestContext) (*httptest.ResponseRecorder, *httperror.HandlerError) {
		r := httptest.NewRequest(http.MethodGet, "/custom_templates/"+templateID+"/file", nil)
		r = mux.SetURLVars(r, map[string]string{"id": templateID})
		ctx := security.StoreRestrictedRequestContext(r, restrictedContext)
		r = r.WithContext(ctx)
		rr := httptest.NewRecorder()
		return rr, handler.customTemplateFile(rr, r)
	}

	t.Run("unknown id should get not found error", func(t *testing.T) {
		_, r := test("0", &security.RestrictedRequestContext{UserID: 1})
		require.NotNil(t, r)
		require.Equal(t, http.StatusNotFound, r.StatusCode)
	})

	t.Run("admin should access adminonly template", func(t *testing.T) {
		rr, r := test("1", &security.RestrictedRequestContext{UserID: 1, IsAdmin: true})
		require.Nil(t, r)
		require.Equal(t, http.StatusOK, rr.Result().StatusCode)
		var res struct{ FileContent string }
		require.NoError(t, json.NewDecoder(rr.Body).Decode(&res))
		require.Equal(t, templateContent, res.FileContent)
	})

	t.Run("std should not access adminonly template", func(t *testing.T) {
		_, r := test("1", &security.RestrictedRequestContext{UserID: 2})
		require.NotNil(t, r)
		require.Equal(t, http.StatusForbidden, r.StatusCode)
	})

	t.Run("std should access template via direct user access", func(t *testing.T) {
		rr, r := test("2", &security.RestrictedRequestContext{UserID: 2})
		require.Nil(t, r)
		require.Equal(t, http.StatusOK, rr.Result().StatusCode)
		var res struct{ FileContent string }
		require.NoError(t, json.NewDecoder(rr.Body).Decode(&res))
		require.Equal(t, templateContent, res.FileContent)
	})

	t.Run("std should access template via team access", func(t *testing.T) {
		rr, r := test("2", &security.RestrictedRequestContext{UserID: 3, UserMemberships: []portainer.TeamMembership{{ID: 1, UserID: 3, TeamID: 1}}})
		require.Nil(t, r)
		require.Equal(t, http.StatusOK, rr.Result().StatusCode)
		var res struct{ FileContent string }
		require.NoError(t, json.NewDecoder(rr.Body).Decode(&res))
		require.Equal(t, templateContent, res.FileContent)
	})

	t.Run("std should not access template without access", func(t *testing.T) {
		_, r := test("2", &security.RestrictedRequestContext{UserID: 4})
		require.NotNil(t, r)
		require.Equal(t, http.StatusForbidden, r.StatusCode)
	})
}
