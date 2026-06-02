package cli

import "errors"

// ErrUnauthorized is returned when a non-admin user attempts to access a resource
// outside their permitted namespace scope.
var ErrUnauthorized = errors.New("unauthorized")
