import { useQuery } from '@tanstack/react-query';

import { withError } from '@/react-tools/react-query';

import { EnvironmentGroupId } from '../../types';
import { getGroup } from '../environment-groups.service';

import { queryKeys } from './query-keys';

export function useGroup(id?: EnvironmentGroupId) {
  return useQuery(queryKeys.group(id), () => getGroup(id!), {
    enabled: !!id,
    ...withError('Failed to load group'),
  });
}
