import { useQuery } from '@tanstack/react-query';

import axios from '@/portainer/services/axios/axios';

import { AuthTypeOption } from '../../account/git-credentials/types';
import { isBE } from '../../feature-flags/feature-flags.service';
import { omitPassword } from '../utils';

interface SearchPayload {
  repository: string;
  keyword: string;
  reference?: string;
  username?: string;
  password?: string;
  authorizationType?: AuthTypeOption;
  tlsSkipVerify?: boolean;
  dirOnly?: boolean;
  createdFromCustomTemplateId?: number;
  stackId?: number;
  fromEdgeStack?: boolean;
}

export function useSearch(payload: SearchPayload, enabled: boolean) {
  return useQuery({
    queryKey: ['gitops', 'search', omitPassword(payload)],
    queryFn: () => searchRepo(payload),

    enabled: isBE && enabled,
    retry: false,
    cacheTime: 0,
  });
}

export async function searchRepo(payload: SearchPayload) {
  const { data } = await axios.post<string[] | null>(
    '/gitops/repo/files/search',
    payload
  );
  return data;
}
