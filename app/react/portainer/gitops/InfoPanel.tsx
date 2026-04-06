import { isEqual } from 'lodash';

import { GitCommitLink } from '@/react/portainer/gitops/GitCommitLink';

interface GitDeploymentState {
  repositoryUrl: string;
  configFilePath: string;
  additionalFiles?: string[];
  commitHash?: string;
}

interface Props {
  type: string;
  currentDeployment: GitDeploymentState;
  nextDeployment?: GitDeploymentState;
}

export function InfoPanel({ type, currentDeployment, nextDeployment }: Props) {
  const hasChanges =
    !!nextDeployment &&
    !isEqual(
      {
        repositoryUrl: currentDeployment.repositoryUrl,
        configFilePath: currentDeployment.configFilePath,
        additionalFiles: currentDeployment.additionalFiles || [],
      },
      {
        repositoryUrl: nextDeployment.repositoryUrl,
        configFilePath: nextDeployment.configFilePath,
        additionalFiles: nextDeployment.additionalFiles || [],
      }
    );

  if (hasChanges) {
    const urlChanged =
      nextDeployment.repositoryUrl !== currentDeployment.repositoryUrl;

    return (
      <div className="text-muted">
        <p>
          <strong>Currently deployed:</strong>
          <br />
          <code className="p-0">{currentDeployment.repositoryUrl}</code>
          {currentDeployment.commitHash ? (
            <>
              {' '}
              at{' '}
              <GitCommitLink
                baseURL={currentDeployment.repositoryUrl}
                commitHash={currentDeployment.commitHash}
              />
            </>
          ) : null}
          <br />
          Config: <code>{deployedFiles(currentDeployment)}</code>
        </p>
        <p>
          <strong>Next deployment:</strong>
          <br />
          {urlChanged && (
            <>
              Repository: <code>{nextDeployment.repositoryUrl}</code>
              <br />
            </>
          )}
          Config: <code>{deployedFiles(nextDeployment)}</code>
        </p>
        <p>Pull from here to redeploy.</p>
      </div>
    );
  }

  return (
    <div className="text-muted">
      <p>
        This {type} was deployed from the git repository{' '}
        <code>{currentDeployment.repositoryUrl}</code> and the current version
        deployed is{' '}
        {currentDeployment.commitHash ? (
          <GitCommitLink
            baseURL={currentDeployment.repositoryUrl}
            commitHash={currentDeployment.commitHash}
          />
        ) : (
          'unknown'
        )}
      </p>
      <p>
        Update <code>{deployedFiles(currentDeployment)}</code> in git and pull
        from here to update the {type}.
      </p>
    </div>
  );
}

function deployedFiles(deployment: GitDeploymentState) {
  return [
    deployment.configFilePath,
    ...(deployment.additionalFiles || []),
  ].join(', ');
}
