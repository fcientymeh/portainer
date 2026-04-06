package stackbuilders

import (
	"context"
	"time"

	portainer "github.com/portainer/portainer/api"
)

type UrlMethodStackBuildProcess interface {
	// Set general stack information
	SetGeneralInfo(payload *StackPayload, endpoint *portainer.Endpoint) UrlMethodStackBuildProcess
	// Set unique stack information, e.g. swarm stack has swarmID, kubernetes stack has namespace
	SetUniqueInfo(payload *StackPayload) UrlMethodStackBuildProcess
	// Deploy stack based on the configuration
	Deploy(ctx context.Context, payload *StackPayload, endpoint *portainer.Endpoint) UrlMethodStackBuildProcess
	// Save the stack information to database
	SaveStack() (*portainer.Stack, error)
	// Get reponse from http request. Use if it is needed
	GetResponse() string
	// Set manifest url
	SetURL(payload *StackPayload) UrlMethodStackBuildProcess
	Error() error
}

type UrlMethodStackBuilder struct {
	StackBuilder
}

func (b *UrlMethodStackBuilder) SetGeneralInfo(payload *StackPayload, endpoint *portainer.Endpoint) UrlMethodStackBuildProcess {
	stackID := b.dataStore.Stack().GetNextIdentifier()
	b.stack.ID = portainer.StackID(stackID)
	b.stack.EndpointID = endpoint.ID
	b.stack.Status = portainer.StackStatusActive
	b.stack.CreationDate = time.Now().Unix()
	return b
}

func (b *UrlMethodStackBuilder) SetUniqueInfo(payload *StackPayload) UrlMethodStackBuildProcess {
	return b
}

func (b *UrlMethodStackBuilder) SetURL(payload *StackPayload) UrlMethodStackBuildProcess {
	return b
}

func (b *UrlMethodStackBuilder) Deploy(ctx context.Context, payload *StackPayload, endpoint *portainer.Endpoint) UrlMethodStackBuildProcess {
	if b.hasError() {
		return b
	}

	// Deploy the stack
	err := b.deploymentConfiger.Deploy(ctx)
	if err != nil {
		b.err = err
		return b
	}

	return b
}

func (b *UrlMethodStackBuilder) GetResponse() string {
	return ""
}

func (b *UrlMethodStackBuilder) Error() error {
	return b.err
}
