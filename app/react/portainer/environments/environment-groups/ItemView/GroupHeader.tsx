import { Layers, Plus, RefreshCw, Trash2 } from 'lucide-react';

import { useTags } from '@/portainer/tags/queries';

import { Button } from '@@/buttons';
import { ResourceDetailHeader } from '@@/ResourceDetailHeader/ResourceDetailHeader';
import { Badge } from '@@/Badge';

import { EnvironmentGroup } from '../types';

interface Props {
  group?: EnvironmentGroup;
  isLoading: boolean;
  onRefresh?: () => void;
  onAddEnvironments?: () => void;
  onDelete?: () => void;
}

export function GroupHeader({
  group,
  isLoading,
  onRefresh,
  onAddEnvironments,
  onDelete,
}: Props) {
  const tagsQuery = useTags();

  const tagBadges = group?.TagIds?.length
    ? group.TagIds.map((tagId) => {
        const tag = tagsQuery.data?.find((t) => t.ID === tagId);
        return (
          <Badge key={tagId} type="info" className="text-xs">
            {tag?.Name ?? `Tag ${tagId}`}
          </Badge>
        );
      })
    : undefined;

  const actionBar = group ? (
    <>
      <div className="flex items-center gap-3">
        <Button
          color="none"
          icon={RefreshCw}
          onClick={() => onRefresh?.()}
          data-cy="group-header-refresh"
        >
          Refresh
        </Button>
        <Button
          color="none"
          icon={Plus}
          onClick={() => onAddEnvironments?.()}
          data-cy="group-header-add-environments"
        >
          Add environments
        </Button>
      </div>
      <div className="flex items-center gap-1">
        <Button
          color="none"
          icon={Trash2}
          onClick={() => onDelete?.()}
          data-cy="group-header-delete"
        >
          Delete
        </Button>
      </div>
    </>
  ) : undefined;

  return (
    <ResourceDetailHeader
      isLoading={isLoading}
      errorMessage={
        !isLoading && !group ? 'Failed to load group details' : undefined
      }
      icon={<Layers className="text-blue-9 th-dark:text-blue-3" />}
      iconBackgroundClassName="bg-blue-3 th-dark:bg-blue-9"
      subtitleLabel="Environment Group"
      subtitleClassName="text-blue-9 th-dark:text-blue-5"
      title={group?.Name || ''}
      badge={tagBadges ? <>{tagBadges}</> : undefined}
      description={group?.Description}
      actionBar={actionBar}
    />
  );
}
