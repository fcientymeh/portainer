import { useMutation, useQueryClient } from '@tanstack/react-query';

import axios, { parseAxiosError } from '@/portainer/services/axios/axios';
import { EnvironmentId } from '@/react/portainer/environments/types';
import { withInvalidate } from '@/react-tools/react-query';

import { buildDockerProxyUrl } from '../../proxy/queries/buildDockerProxyUrl';

import { queryKeys } from './queryKeys';

interface PruneImagesResponse {
  ImagesDeleted: Array<{ Deleted?: string; Untagged?: string }> | null;
  SpaceReclaimed: number;
}

export function usePruneImagesMutation(environmentId: EnvironmentId) {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (options: { all?: boolean }) =>
      pruneImages(environmentId, options),
    ...withInvalidate(queryClient, [queryKeys.base(environmentId)]),
  });
}

async function pruneImages(
  environmentId: EnvironmentId,
  { all = false }: { all?: boolean }
): Promise<PruneImagesResponse> {
  try {
    const { data } = await axios.post<PruneImagesResponse>(
      buildDockerProxyUrl(environmentId, 'images', 'prune'),
      null,
      {
        params: {
          filters: JSON.stringify({ dangling: [all ? 'false' : 'true'] }),
        },
      }
    );
    return data;
  } catch (err) {
    throw parseAxiosError(err, 'Unable to prune images');
  }
}
