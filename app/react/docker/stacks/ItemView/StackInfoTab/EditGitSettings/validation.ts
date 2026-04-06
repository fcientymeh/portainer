import { useMemo } from 'react';
import { boolean, object, SchemaOf } from 'yup';

import { StackType } from '@/react/common/stacks/types';
import { buildGitValidationSchema } from '@/react/portainer/gitops/GitForm';
import { useGitCredentials } from '@/react/portainer/account/git-credentials/git-credentials.service';
import { useCurrentUser } from '@/react/hooks/useUser';

import { envVarValidation } from '@@/form-components/EnvironmentVariablesFieldset';

import { FormValues } from './types';

export function useValidationSchema(
  stackType: StackType
): SchemaOf<FormValues> {
  const { user } = useCurrentUser();
  const gitCredentialsQuery = useGitCredentials(user.Id);

  return useMemo(
    () =>
      object({
        git: buildGitValidationSchema(
          gitCredentialsQuery.data || [],
          false,
          stackType === StackType.Kubernetes ? 'manifest' : 'compose'
        ),
        env: envVarValidation(),
        prune: boolean().default(false),
        redeployNow: boolean().default(false),
      }),
    [gitCredentialsQuery.data, stackType]
  );
}
