import { useMutation, useQueryClient } from '@tanstack/react-query';

import { buildStackUrl } from '@/react/common/stacks/queries/buildUrl';
import { queryKeys } from '@/react/common/stacks/queries/query-keys';
import axios, { parseAxiosError } from '@/portainer/services/axios/axios';

import { EnvVarValues } from '@@/form-components/EnvironmentVariablesFieldset';

import { AuthTypeOption } from '../../account/git-credentials/types';

interface DeployGitPayload {
  RepositoryReferenceName?: string;
  RepositoryAuthentication?: boolean;
  RepositoryUsername?: string;
  RepositoryPassword?: string;
  RepositoryAuthorizationType?: AuthTypeOption;
  Env?: EnvVarValues;
  Prune?: boolean;
  // RepullImageAndRedeploy indicates whether to force repulling images and redeploying the stack
  RepullImageAndRedeploy?: boolean;
  RepositoryGitCredentialID?: number;

  StackName?: string;
}

export async function updateGitStack(
  stackId: number,
  endpointId: number,
  payload: DeployGitPayload
) {
  try {
    const { data } = await axios.put(
      buildStackUrl(stackId, 'git/redeploy'),
      payload,
      { params: { endpointId } }
    );
    return data;
  } catch (e) {
    throw parseAxiosError(e as Error);
  }
}

export function useUpdateGitStack(stackId: number, endpointId: number) {
  const queryClient = useQueryClient();

  return useMutation({
    mutationKey: ['git-stack', 'redeploy', endpointId, stackId],
    mutationFn: (payload: DeployGitPayload) =>
      updateGitStack(stackId, endpointId, payload),
    onSuccess: () => {
      queryClient.invalidateQueries({
        queryKey: queryKeys.stack(stackId),
        exact: true,
      });
    },
  });
}
