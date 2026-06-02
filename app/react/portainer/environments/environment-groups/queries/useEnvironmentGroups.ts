import { useQuery } from '@tanstack/react-query';

import axios, { parseAxiosError } from '@/portainer/services/axios/axios';
import { withError } from '@/react-tools/react-query';

import { EnvironmentGroup } from '../types';

import { queryKeys } from './query-keys';
import { buildUrl } from './build-url';

export function useEnvironmentGroups() {
  return useQuery({
    queryKey: queryKeys.base(),
    queryFn: () => getEnvironmentGroups(),
    ...withError('Unable to retrieve environment groups'),
  });
}

async function getEnvironmentGroups() {
  try {
    const { data } = await axios.get<Array<EnvironmentGroup>>(buildUrl());
    return data;
  } catch (e) {
    throw parseAxiosError(e, 'Unable to retrieve environment groups');
  }
}
