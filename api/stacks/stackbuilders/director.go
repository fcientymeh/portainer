package stackbuilders

import (
	"errors"

	portainer "github.com/portainer/portainer/api"
	httperror "github.com/portainer/portainer/pkg/libhttp/error"
	"github.com/portainer/portainer/pkg/libhttp/request"
)

type StackBuilderDirector struct {
	builder any
}

func NewStackBuilderDirector(b any) *StackBuilderDirector {
	return &StackBuilderDirector{
		builder: b,
	}
}

// Build executes the stack build process based on the builder type. It returns the
// created stack and any error encountered during the process.
// The returned error is of type *httperror.HandlerError, which could be a BadRequest
// or InternalServerError depending on the error encountered during the stack build process.
func (d *StackBuilderDirector) Build(payload *StackPayload, endpoint *portainer.Endpoint) (*portainer.Stack, *httperror.HandlerError) {
	var (
		stack *portainer.Stack
		err   error
	)
	// To align with the flow of the actual service deployment tools, we save
	// the stack before the deployment. This allows us to track the stack
	// metadata and partially created resources.
	switch builder := d.builder.(type) {
	case GitMethodStackBuildProcess:
		stack, err = builder.SetGeneralInfo(payload, endpoint).
			SetUniqueInfo(payload).
			SetGitRepository(payload).
			SaveStack()
		if err != nil {
			return nil, httperror.InternalServerError("Failed to save stack via Git repository method", err)
		}

		// Since AutoUpdate job for stack is created after a successful
		// deployment, we need to update the stack with the new generated job ID
		stack, err = builder.Deploy(payload, endpoint).
			SetAutoUpdate(payload).
			UpdateStack(stack)

	case FileUploadMethodStackBuildProcess:
		stack, err = builder.SetGeneralInfo(payload, endpoint).
			SetUniqueInfo(payload).
			SetUploadedFile(payload).
			SaveStack()
		if err != nil {
			return nil, httperror.InternalServerError("Failed to save stack via File Upload method", err)
		}

		builder.Deploy(payload, endpoint)
		err = builder.Error()

	case FileContentMethodStackBuildProcess:
		stack, err = builder.SetGeneralInfo(payload, endpoint).
			SetUniqueInfo(payload).
			SetFileContent(payload).
			SaveStack()
		if err != nil {
			return nil, httperror.InternalServerError("Failed to save stack via File Content method", err)
		}

		builder.Deploy(payload, endpoint)
		err = builder.Error()

	case UrlMethodStackBuildProcess:
		stack, err = builder.SetGeneralInfo(payload, endpoint).
			SetUniqueInfo(payload).
			SetURL(payload).
			SaveStack()
		if err != nil {
			return nil, httperror.InternalServerError("Failed to save stack via URL method", err)
		}

		builder.Deploy(payload, endpoint)
		err = builder.Error()

	default:
		return nil, httperror.BadRequest("Invalid value for query parameter: method. Value must be one of: string or repository or url or file", errors.New(request.ErrInvalidQueryParameter))
	}
	if err != nil {
		return nil, httperror.InternalServerError("Failed to deploy stack", err)
	}

	return stack, nil
}
