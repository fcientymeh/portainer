import { Edit } from 'lucide-react';

import { FeatureId } from '@/react/portainer/feature-flags/enums';
import Openldap from '@/assets/ico/vendor/openldap.svg?c';

export const SERVER_TYPES = {
  CUSTOM: 0,
  OPEN_LDAP: 1,
  AD: 2,
};

export const options = [
  {
    id: 'ldap_custom',
    icon: Edit,
    iconType: 'badge',
    label: 'Custom',
    value: SERVER_TYPES.CUSTOM,
  },

];
