import { useMutation } from '@tanstack/react-query';

import axios from '@/portainer/services/axios/axios';
import { withError } from '@/react-tools/react-query';

async function testSourceConnection(id: string): Promise<void> {
  await axios.post(`/gitops/sources/${id}/test`);
}

export function useTestSourceConnectionMutation() {
  return useMutation({
    mutationFn: testSourceConnection,
    ...withError('Connection test failed'),
  });
}
