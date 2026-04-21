import { StackDeploymentInfo } from '@/react/common/stacks/types';

import { confirm } from '@@/modals/confirm';

import { GitFormModel, RepoConfigResponse } from './types';

export function getAuthentication(
  model: Pick<
    GitFormModel,
    | 'RepositoryAuthentication'
    | 'RepositoryPassword'
    | 'RepositoryUsername'
    | 'RepositoryGitCredentialID'
  >
) {
  if (!model.RepositoryAuthentication) {
    return undefined;
  }

  if (model.RepositoryGitCredentialID) {
    return { gitCredentialId: model.RepositoryGitCredentialID };
  }

  return {
    username: model.RepositoryUsername,
    password: model.RepositoryPassword,
  };
}

/** Returns a copy of the object without `password` to keep it out of query keys and devtools. */
export function omitPassword<T extends { password?: unknown }>(
  obj: T
): Omit<T, 'password'> {
  const { password, ...rest } = obj;
  return rest;
}

export function confirmEnableTLSVerify() {
  return confirm({
    title: 'Enable TLS Verification?',
    message:
      'Enabling the verification of TLS certificates without ensuring the correct configuration of your Certificate Authority (CA) for self-signed certificates can result in deployment failures.',
  });
}
export function isGitConfigDiverged(
  gitConfig: RepoConfigResponse,
  currentDeploymentInfo: StackDeploymentInfo | null | undefined
) {
  if (!currentDeploymentInfo) return false;

  // treat missing field as unchanged

  const urlChanged =
    typeof currentDeploymentInfo.RepositoryURL !== 'undefined' &&
    currentDeploymentInfo.RepositoryURL !== gitConfig.URL;

  const refChanged =
    typeof currentDeploymentInfo.ReferenceName !== 'undefined' &&
    currentDeploymentInfo.ReferenceName !== gitConfig.ReferenceName;

  const fileChanged =
    typeof currentDeploymentInfo.ConfigFilePath !== 'undefined' &&
    currentDeploymentInfo.ConfigFilePath !== gitConfig.ConfigFilePath;

  return urlChanged || refChanged || fileChanged;
}
