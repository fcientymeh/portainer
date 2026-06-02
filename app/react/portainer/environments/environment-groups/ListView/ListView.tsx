import { useRouter } from '@uirouter/react';
import { Plus } from 'lucide-react';

import { Button } from '@@/buttons';
import { PageHeader } from '@@/PageHeader';

import { EnvironmentGroupsTable } from './EnvironmentGroupsTable/EnvironmentGroupsTable';

export function ListView() {
  const router = useRouter();

  return (
    <>
      <PageHeader
        title="Environment Groups"
        breadcrumbs="Environment group management"
        reload
      >
        <Button
          onClick={() => router.stateService.go('portainer.groups.new')}
          icon={Plus}
          color="primary"
          size="small"
          data-cy="add-environment-group-button"
        >
          Add Group
        </Button>
      </PageHeader>

      <div className="mx-5">
        <EnvironmentGroupsTable />
      </div>
    </>
  );
}
