import { useMemo } from 'react';
import { GitCommit, Settings } from 'lucide-react';
import { useCurrentStateAndParams } from '@uirouter/react';

import { PageHeader } from '@@/PageHeader';
import { Tab, WidgetTabs, useCurrentTabIndex } from '@@/Widget/WidgetTabs';
import { ResourceDetailHeaderSkeleton } from '@@/ResourceDetailHeader/ResourceDetailHeaderSkeleton';
import { Alert } from '@@/Alert';

import { SourceDetail, useSource } from '../queries/useSource';

import { SettingsTab } from './SettingsTab/SettingsTab';
import { WorkflowsTab } from './WorkflowsTab';
import { SourceResourceHeader } from './SourceResourceHeader';
import { CountDot } from './CountDot';

const breadcrumbs = [
  { label: 'GitOps Sources', link: 'portainer.gitops.sources' },
  'Source',
];

export function ItemView() {
  const { params } = useCurrentStateAndParams();
  const sourceId: string = params.sourceId;

  const sourceQuery = useSource(sourceId);
  const source = sourceQuery.data;

  if (sourceQuery.isLoading) {
    return (
      <>
        <PageHeader breadcrumbs={breadcrumbs} />
        <div className="mx-4 mb-4 space-y-4">
          <ResourceDetailHeaderSkeleton statBlockCount={2} />
        </div>
      </>
    );
  }

  if (!source || sourceQuery.isError) {
    const error = sourceQuery.error;

    return (
      <>
        <PageHeader breadcrumbs={breadcrumbs} />
        <div className="mx-4 mb-4 space-y-4">
          <Alert color="error">
            Failed loading source:{' '}
            {error instanceof Error ? error.message : 'Unknown error'}
          </Alert>
        </div>
      </>
    );
  }

  return <PageContent source={source} />;
}

function PageContent({ source }: { source: SourceDetail }) {
  const tabs: Array<Tab> = useMemo(
    () => [
      {
        name: 'Settings',
        icon: Settings,
        widget: <SettingsTab source={source} />,
        selectedTabParam: 'settings',
      },
      {
        name: (
          <>
            Workflows{' '}
            <CountDot value={source?.workflows.length} type="workflow" />
          </>
        ),
        icon: GitCommit,
        widget: <WorkflowsTab workflows={source?.workflows ?? []} />,
        selectedTabParam: 'workflows',
      },
    ],
    [source]
  );

  const currentTabIndex = useCurrentTabIndex(tabs);
  return (
    <>
      <PageHeader
        breadcrumbs={[
          { label: 'GitOps Sources', link: 'portainer.gitops.sources' },
          source.name,
        ]}
        reload
      />
      <div className="mx-4 mb-4 space-y-4">
        <SourceResourceHeader source={source} />
        <WidgetTabs
          tabs={tabs}
          currentTabIndex={currentTabIndex}
          useContainer={false}
        />
        {tabs[currentTabIndex].widget}
      </div>
    </>
  );
}
