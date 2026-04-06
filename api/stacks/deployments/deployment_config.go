package deployments

import "context"

type StackDeploymentConfiger interface {
	GetUsername() string
	Deploy(ctx context.Context) error
	GetResponse() string
}
