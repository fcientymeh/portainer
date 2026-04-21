package docker

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	portainer "github.com/portainer/portainer/api"
	"github.com/portainer/portainer/api/dataservices"
	"github.com/portainer/portainer/api/datastore"
	"github.com/portainer/portainer/api/http/security"
	"github.com/segmentio/encoding/json"
	"github.com/stretchr/testify/require"
)

const serviceCreationAPIVersion = "1.51"

type serviceCreationFixtures struct {
	dockerSrv  *httptest.Server
	ds         dataservices.DataStore
	stdUser    portainer.User
	adminUser  portainer.User
	endpointID portainer.EndpointID
}

func newServiceCreationFixtures(t *testing.T) *serviceCreationFixtures {
	t.Helper()

	const serviceID = "some-service-id"

	dockerSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodHead && r.URL.Path == "/_ping" {
			w.Header().Add("Api-Version", serviceCreationAPIVersion)
			_, _ = w.Write([]byte{})

			return
		}

		if r.Method == http.MethodPost {
			data, err := json.Marshal(map[string]string{"ID": serviceID})
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)

				return
			}

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write(data)

			return
		}

		http.NotFound(w, r)
	}))
	t.Cleanup(dockerSrv.Close)

	_, store := datastore.MustNewTestStore(t, true, false)

	f := &serviceCreationFixtures{
		dockerSrv:  dockerSrv,
		ds:         store,
		stdUser:    portainer.User{ID: 1, Username: "std", Role: portainer.StandardUserRole},
		adminUser:  portainer.User{ID: 2, Username: "admin", Role: portainer.AdministratorRole},
		endpointID: portainer.EndpointID(1),
	}

	err := store.UpdateTx(func(tx dataservices.DataStoreTx) error {
		err := tx.User().Create(&f.stdUser)
		require.NoError(t, err)

		err = tx.User().Create(&f.adminUser)
		require.NoError(t, err)

		err = tx.Endpoint().Create(&portainer.Endpoint{ID: f.endpointID, Name: "test-env"})
		require.NoError(t, err)

		return nil
	})
	require.NoError(t, err)

	return f
}

func (f *serviceCreationFixtures) setSecuritySettings(t *testing.T, settings portainer.EndpointSecuritySettings) {
	t.Helper()

	err := f.ds.UpdateTx(func(tx dataservices.DataStoreTx) error {
		return tx.Endpoint().UpdateEndpoint(f.endpointID, &portainer.Endpoint{
			ID:               f.endpointID,
			Name:             "test-env",
			SecuritySettings: settings,
		})
	})
	require.NoError(t, err)
}

func (f *serviceCreationFixtures) newTransport() *Transport {
	return &Transport{
		endpoint:      &portainer.Endpoint{ID: f.endpointID},
		dataStore:     f.ds,
		HTTPTransport: &http.Transport{},
	}
}

type serviceBody struct {
	TaskTemplate struct {
		ContainerSpec struct {
			CapabilityAdd  []string       `json:"CapabilityAdd,omitempty"`
			CapabilityDrop []string       `json:"CapabilityDrop,omitempty"`
			Sysctls        map[string]any `json:"Sysctls,omitempty"`
			Privileges     *struct {
				Seccomp  *struct{ Mode string } `json:"Seccomp,omitempty"`
				AppArmor *struct{ Mode string } `json:"AppArmor,omitempty"`
			} `json:"Privileges,omitempty"`
			Mounts []struct {
				Type string `json:"Type"`
			} `json:"Mounts,omitempty"`
		} `json:"ContainerSpec"`
	} `json:"TaskTemplate"`
}

func (f *serviceCreationFixtures) newRequest(t *testing.T, body serviceBody, user portainer.User) *http.Request {
	t.Helper()

	data, err := json.Marshal(body)
	require.NoError(t, err)

	req, err := http.NewRequestWithContext(
		t.Context(),
		http.MethodPost,
		f.dockerSrv.URL+"/v"+serviceCreationAPIVersion+"/services/create",
		bytes.NewReader(data),
	)
	require.NoError(t, err)

	return req.WithContext(security.StoreTokenData(req, &portainer.TokenData{
		ID:       user.ID,
		Username: user.Username,
		Role:     user.Role,
	}))
}

var (
	restrictiveSettings = portainer.EndpointSecuritySettings{
		AllowContainerCapabilitiesForRegularUsers: false,
		AllowSysctlSettingForRegularUsers:         false,
		AllowSecurityOptForRegularUsers:           false,
		AllowBindMountsForRegularUsers:            false,
	}

	permissiveSettings = portainer.EndpointSecuritySettings{
		AllowContainerCapabilitiesForRegularUsers: true,
		AllowSysctlSettingForRegularUsers:         true,
		AllowSecurityOptForRegularUsers:           true,
		AllowBindMountsForRegularUsers:            true,
	}
)

func TestDecorateServiceCreationOperation_CapabilityAddForbidden(t *testing.T) {
	f := newServiceCreationFixtures(t)
	f.setSecuritySettings(t, restrictiveSettings)

	var body serviceBody
	body.TaskTemplate.ContainerSpec.CapabilityAdd = []string{"NET_ADMIN"}

	resp, err := f.newTransport().decorateServiceCreationOperation(f.newRequest(t, body, f.stdUser))
	require.ErrorIs(t, err, ErrContainerCapabilitiesForbidden)
	require.NotNil(t, resp)
	require.Equal(t, http.StatusForbidden, resp.StatusCode)

	err = resp.Body.Close()
	require.NoError(t, err)
}

func TestDecorateServiceCreationOperation_CapabilityDropForbidden(t *testing.T) {
	f := newServiceCreationFixtures(t)
	f.setSecuritySettings(t, restrictiveSettings)

	var body serviceBody
	body.TaskTemplate.ContainerSpec.CapabilityDrop = []string{"MKNOD"}

	resp, err := f.newTransport().decorateServiceCreationOperation(f.newRequest(t, body, f.stdUser))

	require.ErrorIs(t, err, ErrContainerCapabilitiesForbidden)
	require.NotNil(t, resp)
	require.Equal(t, http.StatusForbidden, resp.StatusCode)

	err = resp.Body.Close()
	require.NoError(t, err)
}

func TestDecorateServiceCreationOperation_CapabilitiesAllowed(t *testing.T) {
	f := newServiceCreationFixtures(t)
	f.setSecuritySettings(t, permissiveSettings)

	var body serviceBody
	body.TaskTemplate.ContainerSpec.CapabilityAdd = []string{"NET_ADMIN"}

	resp, err := f.newTransport().decorateServiceCreationOperation(f.newRequest(t, body, f.stdUser))
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.NotEqual(t, http.StatusForbidden, resp.StatusCode)

	err = resp.Body.Close()
	require.NoError(t, err)
}

func TestDecorateServiceCreationOperation_NoCapabilitiesAllowed(t *testing.T) {
	f := newServiceCreationFixtures(t)
	f.setSecuritySettings(t, restrictiveSettings)

	var body serviceBody

	resp, err := f.newTransport().decorateServiceCreationOperation(f.newRequest(t, body, f.stdUser))
	require.NotErrorIs(t, err, ErrContainerCapabilitiesForbidden)
	require.NotNil(t, resp)
	require.NotEqual(t, http.StatusForbidden, resp.StatusCode)

	err = resp.Body.Close()
	require.NoError(t, err)
}

func TestDecorateServiceCreationOperation_SysctlForbidden(t *testing.T) {
	f := newServiceCreationFixtures(t)
	f.setSecuritySettings(t, restrictiveSettings)

	var body serviceBody
	body.TaskTemplate.ContainerSpec.Sysctls = map[string]any{"net.ipv4.ip_forward": "1"}

	resp, err := f.newTransport().decorateServiceCreationOperation(f.newRequest(t, body, f.stdUser))

	require.ErrorIs(t, err, ErrSysCtlSettingsForbidden)
	require.NotNil(t, resp)
	require.Equal(t, http.StatusForbidden, resp.StatusCode)

	err = resp.Body.Close()
	require.NoError(t, err)
}

func TestDecorateServiceCreationOperation_SysctlAllowed(t *testing.T) {
	f := newServiceCreationFixtures(t)
	f.setSecuritySettings(t, permissiveSettings)

	var body serviceBody
	body.TaskTemplate.ContainerSpec.Sysctls = map[string]any{"net.ipv4.ip_forward": "1"}

	resp, err := f.newTransport().decorateServiceCreationOperation(f.newRequest(t, body, f.stdUser))

	require.NoError(t, err)
	require.NotNil(t, resp)
	require.NotEqual(t, http.StatusForbidden, resp.StatusCode)

	err = resp.Body.Close()
	require.NoError(t, err)
}

func TestDecorateServiceCreationOperation_SeccompForbidden(t *testing.T) {
	f := newServiceCreationFixtures(t)
	f.setSecuritySettings(t, restrictiveSettings)

	var body serviceBody
	body.TaskTemplate.ContainerSpec.Privileges = &struct {
		Seccomp  *struct{ Mode string } `json:"Seccomp,omitempty"`
		AppArmor *struct{ Mode string } `json:"AppArmor,omitempty"`
	}{
		Seccomp: &struct{ Mode string }{Mode: "custom"},
	}

	resp, err := f.newTransport().decorateServiceCreationOperation(f.newRequest(t, body, f.stdUser))

	require.ErrorIs(t, err, ErrSecurityOptSettingsForbidden)
	require.NotNil(t, resp)
	require.Equal(t, http.StatusForbidden, resp.StatusCode)

	err = resp.Body.Close()
	require.NoError(t, err)
}

func TestDecorateServiceCreationOperation_AppArmorForbidden(t *testing.T) {
	f := newServiceCreationFixtures(t)
	f.setSecuritySettings(t, restrictiveSettings)

	var body serviceBody
	body.TaskTemplate.ContainerSpec.Privileges = &struct {
		Seccomp  *struct{ Mode string } `json:"Seccomp,omitempty"`
		AppArmor *struct{ Mode string } `json:"AppArmor,omitempty"`
	}{
		AppArmor: &struct{ Mode string }{Mode: "localhost"},
	}

	resp, err := f.newTransport().decorateServiceCreationOperation(f.newRequest(t, body, f.stdUser))
	require.ErrorIs(t, err, ErrSecurityOptSettingsForbidden)
	require.NotNil(t, resp)
	require.Equal(t, http.StatusForbidden, resp.StatusCode)

	err = resp.Body.Close()
	require.NoError(t, err)
}

func TestDecorateServiceCreationOperation_NilPrivilegesNotForbidden(t *testing.T) {
	f := newServiceCreationFixtures(t)
	f.setSecuritySettings(t, restrictiveSettings)

	var body serviceBody

	resp, err := f.newTransport().decorateServiceCreationOperation(f.newRequest(t, body, f.stdUser))
	require.NotErrorIs(t, err, ErrSecurityOptSettingsForbidden)
	require.NotNil(t, resp)
	require.NotEqual(t, http.StatusForbidden, resp.StatusCode)

	err = resp.Body.Close()
	require.NoError(t, err)
}

func TestDecorateServiceCreationOperation_PrivilegesWithNilSeccompAndAppArmorNotForbidden(t *testing.T) {
	f := newServiceCreationFixtures(t)
	f.setSecuritySettings(t, restrictiveSettings)

	var body serviceBody
	body.TaskTemplate.ContainerSpec.Privileges = &struct {
		Seccomp  *struct{ Mode string } `json:"Seccomp,omitempty"`
		AppArmor *struct{ Mode string } `json:"AppArmor,omitempty"`
	}{}

	resp, err := f.newTransport().decorateServiceCreationOperation(f.newRequest(t, body, f.stdUser))

	require.NotErrorIs(t, err, ErrSecurityOptSettingsForbidden)
	require.NotNil(t, resp)
	require.NotEqual(t, http.StatusForbidden, resp.StatusCode)

	err = resp.Body.Close()
	require.NoError(t, err)
}

func TestDecorateServiceCreationOperation_PrivilegesAllowed(t *testing.T) {
	f := newServiceCreationFixtures(t)
	f.setSecuritySettings(t, permissiveSettings)

	var body serviceBody
	body.TaskTemplate.ContainerSpec.Privileges = &struct {
		Seccomp  *struct{ Mode string } `json:"Seccomp,omitempty"`
		AppArmor *struct{ Mode string } `json:"AppArmor,omitempty"`
	}{
		Seccomp: &struct{ Mode string }{Mode: "custom"},
	}

	resp, err := f.newTransport().decorateServiceCreationOperation(f.newRequest(t, body, f.stdUser))

	require.NoError(t, err)
	require.NotNil(t, resp)
	require.NotEqual(t, http.StatusForbidden, resp.StatusCode)

	err = resp.Body.Close()
	require.NoError(t, err)
}

func TestDecorateServiceCreationOperation_BindMountForbidden(t *testing.T) {
	f := newServiceCreationFixtures(t)
	f.setSecuritySettings(t, restrictiveSettings)

	var body serviceBody
	body.TaskTemplate.ContainerSpec.Mounts = []struct {
		Type string `json:"Type"`
	}{{Type: "bind"}}

	resp, err := f.newTransport().decorateServiceCreationOperation(f.newRequest(t, body, f.stdUser))
	require.ErrorIs(t, err, ErrBindMountsForbidden)
	require.NotNil(t, resp)
	require.Equal(t, http.StatusForbidden, resp.StatusCode)

	err = resp.Body.Close()
	require.NoError(t, err)
}

func TestDecorateServiceCreationOperation_NonBindMountNotForbidden(t *testing.T) {
	f := newServiceCreationFixtures(t)

	f.setSecuritySettings(t, portainer.EndpointSecuritySettings{
		AllowContainerCapabilitiesForRegularUsers: true,
		AllowSysctlSettingForRegularUsers:         true,
		AllowSecurityOptForRegularUsers:           true,
		AllowBindMountsForRegularUsers:            false,
	})

	var body serviceBody
	body.TaskTemplate.ContainerSpec.Mounts = []struct {
		Type string `json:"Type"`
	}{{Type: "volume"}}

	resp, err := f.newTransport().decorateServiceCreationOperation(f.newRequest(t, body, f.stdUser))

	require.NotErrorIs(t, err, ErrBindMountsForbidden)
	require.NotNil(t, resp)
	require.NotEqual(t, http.StatusForbidden, resp.StatusCode)

	err = resp.Body.Close()
	require.NoError(t, err)
}

func TestDecorateServiceCreationOperation_BindMountAllowed(t *testing.T) {
	f := newServiceCreationFixtures(t)
	f.setSecuritySettings(t, permissiveSettings)

	var body serviceBody
	body.TaskTemplate.ContainerSpec.Mounts = []struct {
		Type string `json:"Type"`
	}{{Type: "bind"}}

	resp, err := f.newTransport().decorateServiceCreationOperation(f.newRequest(t, body, f.stdUser))
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.NotEqual(t, http.StatusForbidden, resp.StatusCode)

	err = resp.Body.Close()
	require.NoError(t, err)
}

func TestDecorateServiceCreationOperation_AdminBypassesAllSecurityChecks(t *testing.T) {
	f := newServiceCreationFixtures(t)
	f.setSecuritySettings(t, restrictiveSettings)

	var body serviceBody
	body.TaskTemplate.ContainerSpec.CapabilityAdd = []string{"NET_ADMIN"}
	body.TaskTemplate.ContainerSpec.CapabilityDrop = []string{"MKNOD"}
	body.TaskTemplate.ContainerSpec.Sysctls = map[string]any{"net.ipv4.ip_forward": "1"}
	body.TaskTemplate.ContainerSpec.Privileges = &struct {
		Seccomp  *struct{ Mode string } `json:"Seccomp,omitempty"`
		AppArmor *struct{ Mode string } `json:"AppArmor,omitempty"`
	}{
		Seccomp: &struct{ Mode string }{Mode: "custom"},
	}
	body.TaskTemplate.ContainerSpec.Mounts = []struct {
		Type string `json:"Type"`
	}{{Type: "bind"}}

	resp, err := f.newTransport().decorateServiceCreationOperation(f.newRequest(t, body, f.adminUser))
	require.NotErrorIs(t, err, ErrContainerCapabilitiesForbidden)
	require.NotErrorIs(t, err, ErrSysCtlSettingsForbidden)
	require.NotErrorIs(t, err, ErrSecurityOptSettingsForbidden)
	require.NotErrorIs(t, err, ErrBindMountsForbidden)
	require.NotNil(t, resp)
	require.NotEqual(t, http.StatusForbidden, resp.StatusCode)

	err = resp.Body.Close()
	require.NoError(t, err)
}

func TestDecorateServiceCreationOperation_StandardUserPermissiveSettingsSucceeds(t *testing.T) {
	f := newServiceCreationFixtures(t)
	f.setSecuritySettings(t, permissiveSettings)

	var body serviceBody
	body.TaskTemplate.ContainerSpec.CapabilityAdd = []string{"NET_ADMIN"}
	body.TaskTemplate.ContainerSpec.Sysctls = map[string]any{"net.core.somaxconn": "128"}
	body.TaskTemplate.ContainerSpec.Mounts = []struct {
		Type string `json:"Type"`
	}{{Type: "bind"}}

	resp, err := f.newTransport().decorateServiceCreationOperation(f.newRequest(t, body, f.stdUser))
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.Equal(t, http.StatusCreated, resp.StatusCode)

	err = resp.Body.Close()
	require.NoError(t, err)
}
