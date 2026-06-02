package source

import (
	portainer "github.com/portainer/portainer/api"
	"github.com/portainer/portainer/api/dataservices"
)

// BucketName represents the name of the bucket where this service stores data.
const BucketName = "sources"

// Service represents a service for managing GitOps source data.
type Service struct {
	dataservices.BaseDataService[portainer.Source, portainer.SourceID]
}

// NewService creates a new instance of a service.
func NewService(connection portainer.Connection) (*Service, error) {
	err := connection.SetServiceName(BucketName)
	if err != nil {
		return nil, err
	}

	return &Service{
		BaseDataService: dataservices.BaseDataService[portainer.Source, portainer.SourceID]{
			Bucket:     BucketName,
			Connection: connection,
		},
	}, nil
}

func (service *Service) Tx(tx portainer.Transaction) ServiceTx {
	return ServiceTx{
		BaseDataServiceTx: dataservices.BaseDataServiceTx[portainer.Source, portainer.SourceID]{
			Bucket:     BucketName,
			Connection: service.Connection,
			Tx:         tx,
		},
	}
}

// Create creates a new source.
func (service *Service) Create(source *portainer.Source) error {
	return service.Connection.CreateObject(
		BucketName,
		func(id uint64) (int, any) {
			source.ID = portainer.SourceID(id)
			return int(source.ID), source
		},
	)
}
