package edgegroups

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	portainer "github.com/portainer/portainer/api"
	"github.com/portainer/portainer/api/datastore"
	"github.com/portainer/portainer/api/internal/testhelpers"
	"github.com/portainer/portainer/api/roar"

	"github.com/segmentio/encoding/json"
	"github.com/stretchr/testify/require"
)

func TestEdgeGroupUpdateHandler(t *testing.T) {
	t.Parallel()
	handler, store := newHandlerWithEdgeEndpoints(t)

	err := store.EdgeGroup().Create(&portainer.EdgeGroup{
		ID:          1,
		Name:        "Test Edge Group",
		EndpointIDs: roar.FromSlice([]portainer.EndpointID{1}),
	})
	require.NoError(t, err)

	rr := httptest.NewRecorder()

	req := httptest.NewRequest(
		http.MethodPut,
		"/edge_groups/1",
		strings.NewReader(`{"Endpoints": [1, 2, 3]}`),
	)

	handler.ServeHTTP(rr, req)
	require.Equal(t, http.StatusOK, rr.Result().StatusCode)

	var responseGroup portainer.EdgeGroup
	err = json.NewDecoder(rr.Body).Decode(&responseGroup)
	require.NoError(t, err)

	require.ElementsMatch(t, []portainer.EndpointID{1, 2, 3}, responseGroup.Endpoints)
}

func TestEdgeGroupUpdatePanic(t *testing.T) {
	t.Parallel()
	_, store := datastore.MustNewTestStore(t, false, true)

	handler := NewHandler(testhelpers.NewTestRequestBouncer())
	handler.DataStore = store

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPut, "/edge_groups/1", strings.NewReader("{}"))

	handler.ServeHTTP(rr, req)
	require.Equal(t, http.StatusNotFound, rr.Result().StatusCode)
}
