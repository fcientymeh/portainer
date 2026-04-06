import { useQuery } from '@tanstack/react-query';

import axios, { parseAxiosError } from '@/portainer/services/axios/axios';

import { AuthTypeOption } from '../../account/git-credentials/types';
import { omitPassword } from '../utils';

export interface GitFilePreviewParams {
  repository: string;
  targetFile: string;
  reference?: string;
  username?: string;
  password?: string;
  authorizationType?: AuthTypeOption;
  gitCredentialId?: number;
  tlsSkipVerify?: boolean;
}

async function getFilePreview(params: GitFilePreviewParams): Promise<string> {
  try {
    const { data } = await axios.post<{ FileContent: string }>(
      '/gitops/repo/file/preview',
      params
    );
    return data.FileContent;
  } catch (e) {
    throw parseAxiosError(e, 'Unable to fetch file from git');
  }
}

export function useGitFilePreview<TData = string>(
  params: GitFilePreviewParams,
  options: { enabled?: boolean; select?: (data: string) => TData } = {}
) {
  const { enabled = true, select } = options;
  return useQuery({
    queryKey: ['gitops', 'file-preview', omitPassword(params)],
    queryFn: () => getFilePreview(params),
    enabled: enabled && !!params.repository && !!params.targetFile,
    select,
    retry: false,
  });
}
