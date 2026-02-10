import { ArrowUpCircle } from 'lucide-react';
import { useState } from 'react';
import clsx from 'clsx';

import { useNodesCount } from '@/react/portainer/system/useNodesCount';
import {
  ContainerPlatform,
  useSystemInfo,
} from '@/react/portainer/system/useSystemInfo';
import { useCurrentUser } from '@/react/hooks/useUser';
import { withEdition } from '@/react/portainer/feature-flags/withEdition';
import { withHideOnExtension } from '@/react/hooks/withHideOnExtension';
import { useUser } from '@/portainer/users/queries/useUser';

import { useSidebarState } from '../useSidebarState';

import { UpgradeDialog } from './UpgradeDialog';

export const UpgradeBEBannerWrapper = withHideOnExtension(
  withEdition(UpgradeBEBanner, 'CE')
);

const enabledPlatforms: Array<ContainerPlatform> = [
  'Docker Standalone',
  'Docker Swarm',
  'Kubernetes',
];

function UpgradeBEBanner() {
  const {
    user: { Id },
  } = useCurrentUser();

  const { isOpen: isSidebarOpen } = useSidebarState();

  const nodesCountQuery = useNodesCount();
  const systemInfoQuery = useSystemInfo();
  const userQuery = useUser(Id);

  const [isOpen, setIsOpen] = useState(false);

  if (!nodesCountQuery.isSuccess || !systemInfoQuery.data || !userQuery.data) {
    return null;
  }

  const systemInfo = systemInfoQuery.data;

  if (
    !enabledPlatforms.includes(systemInfo.platform) &&
    process.env.FORCE_SHOW_UPGRADE_BANNER !== ''
  ) {
    return null;
  }

  return (
    <>

    </>
  );

  function handleClick() {
    setIsOpen(true);
  }
}
