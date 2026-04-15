package git

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/portainer/portainer/api/archive"
	gittypes "github.com/portainer/portainer/api/git/types"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
	githttp "github.com/go-git/go-git/v5/plumbing/transport/http"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setup(t *testing.T) string {
	dir := t.TempDir()
	bareRepoDir := filepath.Join(dir, "test-clone.git")

	file, err := os.OpenFile("./testdata/test-clone-git-repo.tar.gz", os.O_RDONLY, 0o755)
	if err != nil {
		t.Fatal(errors.Wrap(err, "failed to open an archive"))
	}

	if err := archive.ExtractTarGz(file, dir); err != nil {
		t.Fatal(errors.Wrapf(err, "failed to extract file from the archive to a folder %s", dir))
	}

	return bareRepoDir
}

func Test_checkGitError(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		err      error
		expected error
	}{
		{
			name:     "exact repository not found",
			err:      errors.New("repository not found"),
			expected: gittypes.ErrIncorrectRepositoryURL,
		},
		{
			name:     "repository not found with html body",
			err:      errors.New("repository not found: <html><body>404 Not Found</body></html>"),
			expected: gittypes.ErrIncorrectRepositoryURL,
		},
		{
			name:     "authentication required",
			err:      errors.New("authentication required"),
			expected: gittypes.ErrAuthenticationFailure,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := checkGitError(tt.err)
			assert.Equal(t, tt.expected, result)
		})
	}

	t.Run("other error is unchanged", func(t *testing.T) {
		err := errors.New("some other git error")
		assert.EqualError(t, checkGitError(err), "some other git error")
	})
}

func Test_ClonePublicRepository_Shallow(t *testing.T) {
	t.Parallel()
	service := Service{git: NewGitClient(true)} // no need for http client since the test access the repo via file system.
	repositoryURL := setup(t)
	referenceName := "refs/heads/main"

	dir := t.TempDir()
	t.Logf("Cloning into %s", dir)
	err := service.CloneRepository(t.Context(), dir, repositoryURL, referenceName, "", "", false)
	require.NoError(t, err)
	assert.Equal(t, 1, getCommitHistoryLength(t, dir), "cloned repo has incorrect depth")
}

func Test_ClonePublicRepository_NoGitDirectory(t *testing.T) {
	t.Parallel()
	service := Service{git: NewGitClient(false)} // no need for http client since the test access the repo via file system.
	repositoryURL := setup(t)
	referenceName := "refs/heads/main"

	dir := t.TempDir()
	t.Logf("Cloning into %s", dir)
	err := service.CloneRepository(t.Context(), dir, repositoryURL, referenceName, "", "", false)
	require.NoError(t, err)
	assert.NoDirExists(t, filepath.Join(dir, ".git"))
}

func Test_latestCommitID(t *testing.T) {
	t.Parallel()
	service := Service{git: NewGitClient(true)} // no need for http client since the test access the repo via file system.

	repositoryURL := setup(t)
	referenceName := "refs/heads/main"

	id, err := service.LatestCommitID(t.Context(), repositoryURL, referenceName, "", "", false)

	require.NoError(t, err)
	assert.Equal(t, "68dcaa7bd452494043c64252ab90db0f98ecf8d2", id)
}

func Test_ListRefs(t *testing.T) {
	t.Parallel()
	service := Service{git: NewGitClient(true)}

	repositoryURL := setup(t)

	fs, err := service.ListRefs(t.Context(), repositoryURL, "", "", false, false)

	require.NoError(t, err)
	assert.Equal(t, []string{"refs/heads/main"}, fs)
}

func Test_ListFiles(t *testing.T) {
	t.Parallel()
	service := Service{git: NewGitClient(true)}

	repositoryURL := setup(t)
	referenceName := "refs/heads/main"

	fs, err := service.ListFiles(
		t.Context(),
		repositoryURL,
		referenceName,
		"",
		"",
		false,
		false,
		[]string{".yml"},
		false,
	)

	require.NoError(t, err)
	assert.Equal(t, []string{"docker-compose.yml"}, fs)
}

func getCommitHistoryLength(t *testing.T, dir string) int {
	repo, err := git.PlainOpen(dir)
	if err != nil {
		t.Fatalf("can't open a git repo at %s with error %v", dir, err)
	}

	iter, err := repo.Log(&git.LogOptions{All: true})
	if err != nil {
		t.Fatalf("can't get a commit history iterator with error %v", err)
	}

	count := 0
	if err := iter.ForEach(func(_ *object.Commit) error {
		count++
		return nil
	}); err != nil {
		t.Fatalf("can't iterate over the commit history with error %v", err)
	}

	return count
}

func Test_listRefsPrivateRepository(t *testing.T) {
	t.Parallel()
	ensureIntegrationTest(t)

	accessToken := getRequiredValue(t, "GITHUB_PAT")
	username := getRequiredValue(t, "GITHUB_USERNAME")

	client := NewGitClient(false)

	type args struct {
		repositoryUrl string
		username      string
		password      string
	}

	type expectResult struct {
		err       error
		refsCount int
	}

	tests := []struct {
		name   string
		args   args
		expect expectResult
	}{
		{
			name: "list refs of a real private repository",
			args: args{
				repositoryUrl: privateGitRepoURL,
				username:      username,
				password:      accessToken,
			},
			expect: expectResult{
				err:       nil,
				refsCount: 2,
			},
		},
		{
			name: "list refs of a real private repository with incorrect credential",
			args: args{
				repositoryUrl: privateGitRepoURL,
				username:      "test-username",
				password:      "test-token",
			},
			expect: expectResult{
				err: gittypes.ErrAuthenticationFailure,
			},
		},
		{
			name: "list refs of a fake repository without providing credential",
			args: args{
				repositoryUrl: privateGitRepoURL + "fake",
				username:      "",
				password:      "",
			},
			expect: expectResult{
				err: gittypes.ErrAuthenticationFailure,
			},
		},
		{
			name: "list refs of a fake repository",
			args: args{
				repositoryUrl: privateGitRepoURL + "fake",
				username:      username,
				password:      accessToken,
			},
			expect: expectResult{
				err: gittypes.ErrIncorrectRepositoryURL,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			option := &git.ListOptions{}
			if tt.args.username != "" || tt.args.password != "" {
				option.Auth = &githttp.BasicAuth{
					Username: tt.args.username,
					Password: tt.args.password,
				}
			}
			refs, err := client.ListRefs(t.Context(), tt.args.repositoryUrl, option)
			if tt.expect.err == nil {
				require.NoError(t, err)
				if tt.expect.refsCount > 0 {
					assert.NotEmpty(t, refs)
				}
			} else {
				require.Error(t, err)
				assert.Equal(t, tt.expect.err, err)
			}
		})
	}
}

func Test_listFilesPrivateRepository(t *testing.T) {
	t.Parallel()
	ensureIntegrationTest(t)

	client := NewGitClient(false)

	type args struct {
		repositoryUrl string
		referenceName string
		username      string
		password      string
	}

	type expectResult struct {
		shouldFail   bool
		err          error
		matchedCount int
	}

	accessToken := getRequiredValue(t, "GITHUB_PAT")
	username := getRequiredValue(t, "GITHUB_USERNAME")

	tests := []struct {
		name   string
		args   args
		expect expectResult
	}{
		{
			name: "list tree with real repository and head ref but incorrect credential",
			args: args{
				repositoryUrl: privateGitRepoURL,
				referenceName: "refs/heads/main",
				username:      "test-username",
				password:      "test-token",
			},
			expect: expectResult{
				shouldFail: true,
				err:        gittypes.ErrAuthenticationFailure,
			},
		},
		{
			name: "list tree with real repository and head ref but no credential",
			args: args{
				repositoryUrl: privateGitRepoURL,
				referenceName: "refs/heads/main",
				username:      "",
				password:      "",
			},
			expect: expectResult{
				shouldFail: true,
				err:        gittypes.ErrAuthenticationFailure,
			},
		},
		{
			name: "list tree with real repository and head ref",
			args: args{
				repositoryUrl: privateGitRepoURL,
				referenceName: "refs/heads/main",
				username:      username,
				password:      accessToken,
			},
			expect: expectResult{
				err:          nil,
				matchedCount: 15,
			},
		},
		{
			name: "list tree with real repository but non-existing ref",
			args: args{
				repositoryUrl: privateGitRepoURL,
				referenceName: "refs/fake/feature",
				username:      username,
				password:      accessToken,
			},
			expect: expectResult{
				shouldFail: true,
			},
		},
		{
			name: "list tree with fake repository ",
			args: args{
				repositoryUrl: privateGitRepoURL + "fake",
				referenceName: "refs/fake/feature",
				username:      username,
				password:      accessToken,
			},
			expect: expectResult{
				shouldFail: true,
				err:        gittypes.ErrIncorrectRepositoryURL,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			option := &git.CloneOptions{
				URL:           tt.args.repositoryUrl,
				ReferenceName: plumbing.ReferenceName(tt.args.referenceName),
			}
			if tt.args.username != "" || tt.args.password != "" {
				option.Auth = &githttp.BasicAuth{
					Username: tt.args.username,
					Password: tt.args.password,
				}
			}
			paths, err := client.ListFiles(t.Context(), false, option)
			if tt.expect.shouldFail {
				require.Error(t, err)
				if tt.expect.err != nil {
					assert.Equal(t, tt.expect.err, err)
				}
			} else {
				require.NoError(t, err)
				if tt.expect.matchedCount > 0 {
					assert.NotEmpty(t, paths)
				}
			}
		})
	}
}
