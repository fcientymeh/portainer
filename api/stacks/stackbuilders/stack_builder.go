package stackbuilders

import (
	"fmt"

	portainer "github.com/portainer/portainer/api"
	"github.com/portainer/portainer/api/dataservices"
	"github.com/portainer/portainer/api/stacks/deployments"

	"github.com/rs/zerolog/log"
)

type StackBuilder struct {
	stack              *portainer.Stack
	dataStore          dataservices.DataStore
	fileService        portainer.FileService
	stackDeployer      deployments.StackDeployer
	deploymentConfiger deployments.StackDeploymentConfiger
	err                error
	doCleanUp          bool
}

func CreateStackBuilder(dataStore dataservices.DataStore, fileService portainer.FileService, deployer deployments.StackDeployer) StackBuilder {
	return StackBuilder{
		stack:         &portainer.Stack{},
		dataStore:     dataStore,
		fileService:   fileService,
		stackDeployer: deployer,
		doCleanUp:     true,
	}
}

func (b *StackBuilder) SaveStack() (*portainer.Stack, error) {
	defer func() { _ = b.cleanUp() }()

	if b.hasError() {
		return nil, b.err
	}

	if err := b.dataStore.UpdateTx(func(tx dataservices.DataStoreTx) error {
		if err := tx.Stack().Create(b.stack); err != nil {
			b.err = fmt.Errorf("Unable to persist the stack inside the database: %w", err)
			return b.err
		}

		return nil
	}); err != nil {
		return nil, b.err
	}

	b.doCleanUp = false

	return b.stack, nil
}

func (b *StackBuilder) Error() error {
	return b.err
}

func (b *StackBuilder) cleanUp() error {
	if !b.doCleanUp {
		return nil
	}

	if err := b.fileService.RemoveDirectory(b.stack.ProjectPath); err != nil {
		log.Error().Err(err).Msg("unable to cleanup stack creation")
	}

	return nil
}

func (b *StackBuilder) hasError() bool {
	return b.err != nil
}
