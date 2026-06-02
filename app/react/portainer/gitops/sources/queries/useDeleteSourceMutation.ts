import { useMutation, useQueryClient } from '@tanstack/react-query';

import axios from '@/portainer/services/axios/axios';
import { withError } from '@/react-tools/react-query';

import { sourceQueryKeys } from './query-keys';

async function deleteSource(id: string): Promise<void> {
  await axios.delete(`/gitops/sources/${id}`);
}

export function useDeleteSourceMutation() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: deleteSource,
    onSuccess: (_, id) => {
      queryClient.removeQueries({ queryKey: sourceQueryKeys.detail(id) });
      queryClient.invalidateQueries({ queryKey: sourceQueryKeys.all });
    },
    ...withError('Unable to delete source'),
  });
}
