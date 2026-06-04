import { useQuery } from '@tanstack/react-query';

import { getEndpointGroupsById } from '@api/sdk.gen';
import { PortainerEndpointGroup } from '@api/types.gen';

import { withError } from '@/react-tools/react-query';

import { queryKeys } from './query-keys';

/** Get the environment group by id. **Only portainer administrators can access this endpoint.** */
export function useGroup<T = PortainerEndpointGroup>(
  groupId?: PortainerEndpointGroup['Id'],
  {
    select,
    enabled = true,
  }: {
    select?: (group: PortainerEndpointGroup | null) => T;
    enabled?: boolean;
  } = {}
) {
  return useQuery(
    queryKeys.group(groupId),
    async () => {
      if (groupId === undefined) {
        return null;
      }
      const { data } = await getEndpointGroupsById({ path: { id: groupId } });

      return data;
    },
    {
      staleTime: 50,
      select,
      enabled: enabled && groupId !== undefined,
      ...withError('Failed loading group'),
    }
  );
}
