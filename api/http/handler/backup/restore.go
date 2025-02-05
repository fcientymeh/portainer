package backup

import (
	"bytes"
	"io"
	"log"
	"net/http"

	"github.com/pkg/errors"

	operations "github.com/portainer/portainer/api/backup"
	httperrors "github.com/portainer/portainer/api/http/errors"
	"github.com/portainer/portainer/api/http/security"
	httperror "github.com/portainer/portainer/pkg/libhttp/error"
	"github.com/portainer/portainer/pkg/libhttp/request"
)

type restorePayload struct {
	FileContent []byte
	FileName    string
	Password    string
}

// @id Restore
// @summary Triggers a system restore using provided backup file
// @description Triggers a system restore using provided backup file
// @description **Access policy**: public
// @tags backup
// @accept json
// @param restorePayload body restorePayload true "Restore request payload"
// @success 200 "Success"
// @failure 400 "Invalid request"
// @failure 500 "Server error"
// @router /restore [post]
func (h *Handler) restore(w http.ResponseWriter, r *http.Request) *httperror.HandlerError {
	initialized, err := h.adminMonitor.WasInitialized()
	if err != nil {
		return httperror.InternalServerError("Failed to check system initialization", err)
	}
	//--- AIS: Read-Only user management ---
	uzer, errorek := security.RetrieveTokenData(r)
	teamMemberships, _ := h.dataStore.TeamMembership().TeamMembershipsByUserID(uzer.ID)
	team, err := h.dataStore.Team().TeamByName("READONLY")
	if err != nil {
		log.Printf("[AIP AUDIT] [%s] [WARNING! TEAM READONLY DOES NOT EXIST]     [NONE]", uzer.Username)
	}
	for _, membership := range teamMemberships {
		if membership.TeamID == team.ID {
			if r.Method != http.MethodGet {
				return &httperror.HandlerError{StatusCode: http.StatusForbidden, Message: "Permission DENIED. READONLY ROLE", Err: httperrors.ErrResourceAccessDenied}
			}
		}
	}
	//------------------------
	if initialized {
		return httperror.BadRequest("Cannot restore already initialized instance", errors.New("system already initialized"))
	}
	h.adminMonitor.Stop()
	defer h.adminMonitor.Start()

	var payload restorePayload
	err = decodeForm(r, &payload)
	if err != nil {
		return httperror.BadRequest("Invalid request payload", err)
	}

	var archiveReader io.Reader = bytes.NewReader(payload.FileContent)
	err = operations.RestoreArchive(archiveReader, payload.Password, h.filestorePath, h.gate, h.dataStore, h.shutdownTrigger)
	if err != nil {
		return httperror.InternalServerError("Failed to restore the backup", err)
	}
	//------------ AIP AISECLAB MOD START------------------------
	//
	if errorek == nil {
		if r.Method != http.MethodGet {
			log.Printf("[AIP AUDIT] [%s] [RESTORE PORTAINER BACKUP]     [%s]", uzer.Username, r)
		}
	}
	//
	//------------ AIP AISECLAB MOD END------------------------

	return nil
}

func decodeForm(r *http.Request, p *restorePayload) error {
	content, name, err := request.RetrieveMultiPartFormFile(r, "file")
	if err != nil {
		return err
	}
	p.FileContent = content
	p.FileName = name

	password, _ := request.RetrieveMultiPartFormValue(r, "password", true)
	p.Password = password
	return nil
}
