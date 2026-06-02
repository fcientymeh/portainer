import { createColumnHelper } from '@tanstack/react-table';
import { RefreshCw, Trash2 } from 'lucide-react';

import { Authorized } from '@/react/hooks/useUser';
import { formatDate } from '@/portainer/filters/filters';
import { pluralize } from '@/react/common/string-utils';

import { Badge } from '@@/Badge';
import { Tooltip } from '@@/Tip/Tooltip';
import { Link } from '@@/Link';
import { Icon } from '@@/Icon';
import { TooltipWithChildren } from '@@/Tip/TooltipWithChildren';
import { LoadingButton } from '@@/buttons';
import { ModalType } from '@@/modals';
import { confirm, confirmDelete } from '@@/modals/confirm';
import { buildConfirmButton } from '@@/modals/utils';

import { PodRowData } from '../types';

const columnHelper = createColumnHelper<PodRowData>();

const pod = columnHelper.accessor('podName', {
  header: 'Pod',
  id: 'podName',
  cell: ({ row: { original: podRow } }) => {
    const statusData = podRow.status;
    return (
      <div className="flex min-w-0 items-center gap-2">
        <span className="truncate" title={podRow.podName}>
          {podRow.podName}
        </span>
        <Badge type={statusData.type}>
          <span>
            {statusData.status}
            {statusData.restartCount
              ? ` (Restarted ${statusData.restartCount} ${pluralize(
                  statusData.restartCount,
                  'time'
                )})`
              : ''}
          </span>
          {statusData.message && <Tooltip message={statusData.message} />}
        </Badge>
      </div>
    );
  },
});

const node = columnHelper.accessor('nodeName', {
  header: 'Node',
  cell: ({ getValue }) => {
    const nodeName = getValue();
    return (
      <Authorized
        authorizations="K8sClusterNodeR"
        childrenUnauthorized={nodeName}
      >
        <Link
          to="kubernetes.cluster.node"
          params={{ nodeName }}
          data-cy={`application-container-node-${nodeName}`}
        >
          <div className="max-w-xs truncate" title={nodeName}>
            {nodeName}
          </div>
        </Link>
      </Authorized>
    );
  },
});

const podIp = columnHelper.accessor('podIp', {
  header: 'Pod IP',
  id: 'podIp',
});

const containers = columnHelper.accessor(
  (row) => `${row.readyContainers}/${row.totalContainers}`,
  {
    id: 'containers',
    header: 'Containers',
    enableSorting: false,
  }
);

const creationDate = columnHelper.accessor(
  (row) => formatDate(row.creationDate),
  {
    header: 'Creation Date',
    cell: ({ getValue }) => getValue(),
  }
);

export const podColumns = [pod, node, podIp, containers, creationDate];

interface PodColumnsOptions {
  supportsPodRestart: boolean;
  onRestart: (podName: string) => void;
  onDelete: (podName: string) => void;
  isRestarting: boolean;
  isDeleting: boolean;
  isLoading: boolean;
}

export function getPodColumns({
  supportsPodRestart,
  onRestart,
  onDelete,
  isRestarting,
  isDeleting,
  isLoading,
}: PodColumnsOptions) {
  const actions = columnHelper.display({
    id: 'actions',
    header: 'Actions',
    cell: ({ row: { original: podRow } }) => {
      const restartButton = (
        <LoadingButton
          color="link"
          className="!ml-0"
          disabled={!supportsPodRestart}
          isLoading={isLoading || isDeleting || isRestarting}
          loadingText="Loading"
          data-cy={`application-pod-restart-${podRow.podName}`}
          onClick={async () => {
            const confirmed = await confirm({
              title: 'Are you sure?',
              modalType: ModalType.Warn,
              confirmButton: buildConfirmButton('Restart'),
              message: `All containers in pod '${podRow.podName}' will be restarted in place. The pod itself will not be rescheduled. Do you wish to continue?`,
            });
            if (!confirmed) {
              return;
            }
            onRestart(podRow.podName);
          }}
        >
          <Icon icon={RefreshCw} />
        </LoadingButton>
      );

      return (
        <Authorized authorizations="K8sApplicationsP">
          <div className="flex gap-x-2">
            {supportsPodRestart || isLoading ? (
              <TooltipWithChildren message="Restart pod" position="top">
                {restartButton}
              </TooltipWithChildren>
            ) : (
              <TooltipWithChildren
                message="Restart is disabled because this cluster does not expose the `pods/restart` subresource. Enable `PodRestart` feature gate on the API server and run Kubernetes 1.35 or newer then refresh."
                position="top"
              >
                {restartButton}
              </TooltipWithChildren>
            )}
            <TooltipWithChildren message="Delete pod" position="top">
              <LoadingButton
                color="dangerlight"
                className="!ml-0"
                isLoading={isLoading || isDeleting || isRestarting}
                loadingText="Loading"
                data-cy={`application-pod-delete-${podRow.podName}`}
                onClick={async () => {
                  const confirmed = await confirmDelete(
                    `Are you sure you want to delete pod '${podRow.podName}'? Kubernetes will reschedule a new pod to replace it.`
                  );
                  if (!confirmed) {
                    return;
                  }
                  onDelete(podRow.podName);
                }}
              >
                <Icon icon={Trash2} />
              </LoadingButton>
            </TooltipWithChildren>
          </div>
        </Authorized>
      );
    },
  });

  return [pod, node, podIp, containers, creationDate, actions];
}
