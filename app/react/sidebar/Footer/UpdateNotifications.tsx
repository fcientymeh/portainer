import clsx from 'clsx';
import { DownloadCloud } from 'lucide-react';

import { useUIState } from '@/react/hooks/useUIState';
import { useSystemVersion } from '@/react/portainer/system/useSystemVersion';

import { Icon } from '@@/Icon';

import styles from './UpdateNotifications.module.css';

export function UpdateNotification() {
  const uiStateStore = useUIState();
  const query = useSystemVersion();

  if (!query.data || !query.data.UpdateAvailable) {
    return null;
  }

  const { LatestVersion } = query.data;

  if (
    !!uiStateStore.dismissedUpdateVersion &&
    LatestVersion?.length > 0 &&
    uiStateStore.dismissedUpdateVersion === LatestVersion
  ) {
    return null;
  }

  return (
    <div
      className={clsx(
        styles.root,
        'rounded border py-2',
        'bg-blue-11 th-dark:bg-gray-warm-11',
        'border-blue-9 th-dark:border-gray-warm-9'
      )}
    >



    </div>
  );

  function onDismiss(version: string) {
    uiStateStore.dismissUpdateVersion(version);
  }
}
