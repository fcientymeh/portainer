import { GitFormModel } from '@/react/portainer/gitops/types';

import { EnvVarValues } from '@@/form-components/EnvironmentVariablesFieldset';

export interface FormValues {
  git: GitFormModel;
  env: EnvVarValues;
  prune: boolean;
  redeployNow: boolean;
}
