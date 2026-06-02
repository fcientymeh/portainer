import { GitBranch, GitCommitIcon, ClockIcon } from 'lucide-react';
import moment from 'moment';

import { Icon } from '@@/Icon';
import { ResourceDetailHeader } from '@@/ResourceDetailHeader/ResourceDetailHeader';
import { HeaderStats } from '@@/ResourceDetailHeader/HeaderStats';
import { ResourceStatBlock } from '@@/ResourceDetailHeader/ResourceStatBlock';

import { StatusBadge } from '../../WorkflowsView/WorkflowBadges';
import { SOURCE_TYPES } from '../types';
import { SourceDetail } from '../queries/useSource';

interface Props {
  source: SourceDetail;
}

export function SourceResourceHeader({ source }: Props) {
  const typeConfig = source.type ? SOURCE_TYPES[source.type] : undefined;
  const typeIcon = typeConfig?.icon;
  const lastSyncLabel = source.lastSync
    ? moment.unix(source.lastSync).fromNow()
    : '-';

  return (
    <ResourceDetailHeader
      icon={<Icon icon={typeIcon ?? GitBranch} size="xl" />}
      subtitleLabel={typeConfig?.label ?? 'Git'}
      title={source.name}
      badge={<StatusBadge status={source.status} />}
      description={
        !!source.url && (
          <code className="bg-transparent p-0 tracking-widest th-dark:text-gray-6">
            {source.url}
          </code>
        )
      }
      rightInfo={
        <HeaderStats>
          <ResourceStatBlock>
            <ResourceStatBlock.Label icon={<Icon icon={GitCommitIcon} />}>
              Workflows
            </ResourceStatBlock.Label>
            <ResourceStatBlock.Value align="center" size="base">
              {source.usedBy ?? '-'}
            </ResourceStatBlock.Value>
          </ResourceStatBlock>
          <ResourceStatBlock>
            <ResourceStatBlock.Label icon={<Icon icon={ClockIcon} />}>
              Last sync
            </ResourceStatBlock.Label>
            <ResourceStatBlock.Value align="center" size="base">
              {lastSyncLabel}
            </ResourceStatBlock.Value>
          </ResourceStatBlock>
        </HeaderStats>
      }
    />
  );
}
