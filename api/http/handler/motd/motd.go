package motd

import (
	"net/http"

	_ "github.com/portainer/portainer/api/motd"
)

// @id MOTD
// @summary fetches the message of the day
// @description **Access policy**: restricted
// @tags motd
// @security ApiKeyAuth
// @security jwt
// @produce json
// @success 200 {object} motd.Motd
// @router /motd [get]
func (handler *Handler) motd(w http.ResponseWriter, r *http.Request) {
	return // AIP MOD - totally motd

}
