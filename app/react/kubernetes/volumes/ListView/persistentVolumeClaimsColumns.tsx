import { createColumnHelper } from '@tanstack/react-table';
import { slugify } from 'markdown-to-jsx';
import { Edit } from 'lucide-react';

import { formatDate } from '@/portainer/filters/filters';

import { StatusBadge, StatusBadgeType } from '@@/StatusBadge';
import { Link } from '@@/Link';
import { TooltipWithChildren } from '@@/Tip/TooltipWithChildren';
import { Button } from '@@/buttons';
import { Icon } from '@@/Icon';

import { PersistentVolumeClaim, PersistentVolumeClaimPhase } from './types';

const helper = createColumnHelper<PersistentVolumeClaim>();

export function createPersistentVolumeClaimsColumns(
  onEditResizeClaim: (claim: PersistentVolumeClaim) => void
) {
  return [
    helper.accessor('name', {
      header: 'Name',
      cell: ({ row: { original } }) => {
        return original.namespace && original.name ? (
          <Link
            to="kubernetes.volumes.volume"
            params={{
              namespace: original.namespace,
              name: original.name,
            }}
            data-cy={`volume-link-${original.name}`}
          >
            {original.name}
          </Link>
        ) : (
          <>{original.name}</>
        );
      },
    }),
    helper.accessor('namespace', {
      header: 'Namespace',
    }),
    helper.accessor('phase', {
      header: 'Status',
      cell: ({ getValue }) => {
        const phase = getValue();
        return <StatusBadge color={phaseColor(phase)}>{phase}</StatusBadge>;
      },
    }),
    helper.accessor('storageRequest', {
      header: 'Capacity',
    }),
    helper.accessor((row) => row.humanReadableAccessModes.join(', '), {
      header: 'Access modes',
      id: 'accessModes',
    }),
    helper.accessor('storageClass', {
      header: 'Storage class',
    }),
    helper.accessor('volumeName', {
      header: 'Volume',
    }),
    helper.accessor((row) => formatDate(row.creationDate), {
      header: 'Created',
      id: 'created',
    }),
    helper.display({
      id: 'actions',
      header: 'Actions',
      cell: ({ row: { original } }) => {
        const isExpandable = original.allowVolumeExpansion;
        return (
          <TooltipWithChildren
            message={
              isExpandable
                ? 'Resize volume claim'
                : 'Storage class does not allow volume expansion'
            }
            position="top"
          >
            <Button
              color="light"
              className="!ml-0"
              disabled={!isExpandable}
              data-cy={`kubernetes-pv-resize-edit-${slugify(original.name)}`}
              onClick={() => onEditResizeClaim(original)}
            >
              <Icon icon={Edit} />
            </Button>
          </TooltipWithChildren>
        );
      },
    }),
  ];
}

function phaseColor(phase: PersistentVolumeClaimPhase): StatusBadgeType {
  switch (phase) {
    case 'Bound':
      return 'successLite';
    case 'Pending':
      return 'warningLite';
    case 'Lost':
      return 'dangerLite';
    default:
      return 'mutedLite';
  }
}
