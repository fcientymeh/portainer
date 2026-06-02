package source

import (
	portainer "github.com/portainer/portainer/api"
	"github.com/portainer/portainer/api/dataservices"
)

type ServiceTx struct {
	dataservices.BaseDataServiceTx[portainer.Source, portainer.SourceID]
}

// Create creates a new source.
func (service ServiceTx) Create(source *portainer.Source) error {
	return service.Tx.CreateObject(
		BucketName,
		func(id uint64) (int, any) {
			source.ID = portainer.SourceID(id)
			return int(source.ID), source
		},
	)
}
