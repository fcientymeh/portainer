import { useQuery } from '@tanstack/react-query';

import axios from '@/portainer/services/axios/axios';
import { withError } from '@/react-tools/react-query';

import { Source } from '../types';
import { Workflow } from '../../WorkflowsView/types';

import { sourceQueryKeys } from './query-keys';

export interface ConnectionInfo {
  referenceName: string;
  configFilePath: string;
  tlsSkipVerify: boolean;
  authentication?: boolean;
}

export interface AutoUpdateInfo {
  mechanism?: string;
  fetchInterval?: string;
}

export interface SourceDetail extends Source {
  connection?: ConnectionInfo;
  autoUpdate?: AutoUpdateInfo;
  workflows: Workflow[];
}

async function getSource(id: string): Promise<SourceDetail> {
  const { data } = await axios.get<SourceDetail>(`/gitops/sources/${id}`);
  return data;
}

export function useSource(id: string | undefined) {
  return useQuery({
    queryKey: sourceQueryKeys.detail(id ?? ''),
    queryFn: () => getSource(id!),
    enabled: !!id,
    ...withError('Failed loading source'),
  });
}
