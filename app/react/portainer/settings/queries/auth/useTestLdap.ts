import { useMutation } from '@tanstack/react-query';

import axios, { parseAxiosError } from '@/react/portainer/services/axios/axios';
import { withGlobalError } from '@/react-tools/react-query';
import { LDAPSettings } from '@/react/portainer/settings/types';

export function useTestLdapMutation() {
  return useMutation({
    mutationFn: testLdapLogin,
    ...withGlobalError('Unable to test login'),
  });
}

export async function testLdapLogin({
  password,
  settings,
  username,
}: {
  settings: LDAPSettings;
  username: string;
  password: string;
}): Promise<{ valid: boolean }> {
  try {
    const { data } = await axios.post<{ valid: boolean }>('/ldap/test', {
      LDAPSettings: settings,
      Username: username,
      Password: password,
    });
    return data;
  } catch (e) {
    throw parseAxiosError(e, 'Unable to test login');
  }
}
