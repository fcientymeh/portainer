package exec

import (
	"context"
	"testing"

	portainer "github.com/portainer/portainer/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConfigFilePaths(t *testing.T) {
	t.Parallel()
	args := []string{"stack", "deploy", "--with-registry-auth"}
	filePaths := []string{"dir/file", "dir/file-two", "dir/file-three"}
	expected := []string{"stack", "deploy", "--with-registry-auth", "--compose-file", "dir/file", "--compose-file", "dir/file-two", "--compose-file", "dir/file-three"}
	output := configureFilePaths(args, filePaths)
	assert.ElementsMatch(t, expected, output, "wrong output file paths")
}

func TestPrepareDockerCommandAndArgs(t *testing.T) {
	t.Parallel()
	binaryPath := "/test/dist"
	configPath := "/test/config"
	manager := &SwarmStackManager{
		binaryPath: binaryPath,
		configPath: configPath,
	}

	endpoint := &portainer.Endpoint{
		URL: "tcp://test:9000",
		TLSConfig: portainer.TLSConfiguration{
			TLS:           true,
			TLSSkipVerify: true,
		},
	}

	command, args, err := manager.prepareDockerCommandAndArgs(binaryPath, configPath, endpoint)
	require.NoError(t, err)

	expectedCommand := "/test/dist/docker"
	expectedArgs := []string{"--config", "/test/config", "-H", "tcp://test:9000", "--tls", "--tlscacert", ""}

	require.Equal(t, expectedCommand, command)
	require.Equal(t, expectedArgs, args)
}

func TestRunCommandAndCaptureStdErr(t *testing.T) {
	t.Parallel()

	t.Run("should return nil on successful command", func(t *testing.T) {
		err := runCommandAndCaptureStdErr(context.Background(), "echo", []string{"hello"}, nil, "")
		require.NoError(t, err)
	})

	t.Run("should capture stderr on failure", func(t *testing.T) {
		err := runCommandAndCaptureStdErr(context.Background(), "sh", []string{"-c", "echo 'stderr error' >&2; exit 1"}, nil, "")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "stderr error")
	})

	t.Run("should fall back to stdout when stderr is empty", func(t *testing.T) {
		err := runCommandAndCaptureStdErr(context.Background(), "sh", []string{"-c", "echo 'stdout error'; exit 1"}, nil, "")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "stdout error")
	})

	t.Run("should fall back to exec error when both are empty", func(t *testing.T) {
		err := runCommandAndCaptureStdErr(context.Background(), "sh", []string{"-c", "exit 1"}, nil, "")
		require.Error(t, err)
		assert.NotEmpty(t, err.Error())
		assert.Contains(t, err.Error(), "exit status 1")
	})

	t.Run("should prefer stderr over stdout", func(t *testing.T) {
		err := runCommandAndCaptureStdErr(context.Background(), "sh", []string{"-c", "echo 'stdout msg'; echo 'stderr msg' >&2; exit 1"}, nil, "")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "stderr msg")
		assert.NotContains(t, err.Error(), "stdout msg")
	})

	t.Run("should return error for non-existent command", func(t *testing.T) {
		err := runCommandAndCaptureStdErr(context.Background(), "nonexistent-cmd-12345", nil, nil, "")
		require.Error(t, err)
	})
}
