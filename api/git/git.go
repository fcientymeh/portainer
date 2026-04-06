package git

import (
	"context"
	"os"
	"path/filepath"
	"strings"

	gittypes "github.com/portainer/portainer/api/git/types"
	"github.com/rs/zerolog/log"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/config"
	"github.com/go-git/go-git/v5/plumbing/filemode"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/go-git/go-git/v5/storage/memory"
	"github.com/pkg/errors"
)

type gitClient struct {
	preserveGitDirectory bool
}

func NewGitClient(preserveGitDir bool) *gitClient {
	return &gitClient{
		preserveGitDirectory: preserveGitDir,
	}
}

func (c *gitClient) Download(ctx context.Context, dst string, opt *git.CloneOptions) error {
	_, err := git.PlainCloneContext(ctx, dst, false, opt)
	if err != nil {
		if err.Error() == "authentication required" {
			return gittypes.ErrAuthenticationFailure
		}
		return errors.Wrap(err, "failed to clone git repository")
	}

	if !c.preserveGitDirectory {
		err := os.RemoveAll(filepath.Join(dst, ".git"))
		if err != nil {
			log.Error().Err(err).Msg("failed to remove .git directory")
		}
	}

	return nil
}

func (c *gitClient) LatestCommitID(ctx context.Context, repositoryUrl, referenceName string, opt *git.ListOptions) (string, error) {
	remote := git.NewRemote(memory.NewStorage(), &config.RemoteConfig{
		Name: "origin",
		URLs: []string{repositoryUrl},
	})

	refs, err := remote.List(opt)
	if err != nil {
		if err.Error() == "authentication required" {
			return "", gittypes.ErrAuthenticationFailure
		}
		return "", errors.Wrap(err, "failed to list repository refs")
	}

	if referenceName == "" {
		for _, ref := range refs {
			if strings.EqualFold(ref.Name().String(), "HEAD") {
				referenceName = ref.Target().String()
			}
		}
	}

	for _, ref := range refs {
		if strings.EqualFold(ref.Name().String(), referenceName) {
			return ref.Hash().String(), nil
		}
	}

	return "", errors.Errorf("could not find ref %q in the repository", referenceName)
}

func (c *gitClient) ListRefs(ctx context.Context, repositoryUrl string, opt *git.ListOptions) ([]string, error) {
	rem := git.NewRemote(memory.NewStorage(), &config.RemoteConfig{
		Name: "origin",
		URLs: []string{repositoryUrl},
	})

	refs, err := rem.List(opt)
	if err != nil {
		return nil, checkGitError(err)
	}

	var ret []string
	for _, ref := range refs {
		if ref.Name().String() == "HEAD" {
			continue
		}
		ret = append(ret, ref.Name().String())
	}

	return ret, nil
}

// listFiles list all filenames under the specific repository
func (c *gitClient) ListFiles(ctx context.Context, dirOnly bool, opt *git.CloneOptions) ([]string, error) {
	repo, err := git.Clone(memory.NewStorage(), nil, opt)
	if err != nil {
		return nil, checkGitError(err)
	}

	head, err := repo.Head()
	if err != nil {
		return nil, err
	}

	commit, err := repo.CommitObject(head.Hash())
	if err != nil {
		return nil, err
	}

	tree, err := commit.Tree()
	if err != nil {
		return nil, err
	}

	var allPaths []string

	w := object.NewTreeWalker(tree, true, nil)
	defer w.Close()

	for {
		name, entry, err := w.Next()
		if err != nil {
			break
		}

		isDir := entry.Mode == filemode.Dir
		if dirOnly == isDir {
			allPaths = append(allPaths, name)
		}
	}

	return allPaths, nil
}

func checkGitError(err error) error {
	errMsg := err.Error()
	if strings.Contains(errMsg, "repository not found") {
		return gittypes.ErrIncorrectRepositoryURL
	} else if errMsg == "authentication required" {
		return gittypes.ErrAuthenticationFailure
	}
	return err
}
