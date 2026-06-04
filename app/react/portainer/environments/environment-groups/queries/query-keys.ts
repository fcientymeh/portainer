import { EnvironmentGroupId } from '../../types';

export const queryKeys = {
  base: (size: boolean = false) => ['environment-groups', size] as const,
  group: (id?: EnvironmentGroupId) => [...queryKeys.base(false), id] as const,
};
