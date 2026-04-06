import { useMutation, useQueryClient } from '@tanstack/react-query';

import { Stack } from '@/react/common/stacks/types';
import { updateGitStack } from '@/react/portainer/gitops/queries/useUpdateGitStack';
import {
  GitStackPayload,
  updateGitStackSettings,
} from '@/react/portainer/gitops/queries/useUpdateGitStackSettings';
import { queryKeys } from '@/react/common/stacks/queries/query-keys';

interface MutationArgs {
  payload: GitStackPayload;
  repullImageAndRedeploy?: boolean;
}

export function useUpdateGitStack(stack: Stack) {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: async ({ payload, repullImageAndRedeploy }: MutationArgs) => {
      await updateGitStackSettings(stack.Id, stack.EndpointId, payload);

      if (repullImageAndRedeploy === undefined) {
        return { redeployAttempted: false, redeployFailed: false };
      }

      try {
        await updateGitStack(stack.Id, stack.EndpointId, {
          Env: payload.env,
          Prune: payload.prune,
          RepositoryAuthentication: payload.RepositoryAuthentication,
          RepositoryAuthorizationType: payload.RepositoryAuthorizationType,
          StackName: undefined, // TODO: in kubernetes
          RepositoryGitCredentialID: payload.RepositoryGitCredentialID,
          RepositoryPassword: payload.RepositoryPassword,
          RepositoryReferenceName: payload.RepositoryReferenceName,
          RepositoryUsername: payload.RepositoryUsername,
          RepullImageAndRedeploy: repullImageAndRedeploy,
        });
        return { redeployAttempted: true, redeployFailed: false };
      } catch (error) {
        return {
          redeployAttempted: true,
          redeployFailed: true,
          redeployError: error,
        };
      }
    },
    onSuccess: () => {
      queryClient.invalidateQueries({
        queryKey: queryKeys.stack(stack.Id),
        exact: true,
      });
    },
  });
}
