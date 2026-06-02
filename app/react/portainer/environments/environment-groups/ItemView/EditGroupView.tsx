import { useRouter } from '@uirouter/react';
import { useMemo } from 'react';
import { FormikHelpers } from 'formik';
import { useQueryClient } from '@tanstack/react-query';

import { useIdParam } from '@/react/hooks/useIdParam';
import { notifySuccess } from '@/portainer/services/notifications';

import { Widget } from '@@/Widget';
import { PageHeader } from '@@/PageHeader';
import { Alert } from '@@/Alert';
import { DeleteButton } from '@@/buttons/DeleteButton';

import { useGroup } from '../queries/useGroup';
import { useUpdateGroupMutation } from '../queries/useUpdateGroupMutation';
import { useDeleteEnvironmentGroupMutation } from '../queries/useDeleteEnvironmentGroupMutation';
import { queryKeys } from '../queries/query-keys';
import { GroupForm, GroupFormValues } from '../components/GroupForm';
import { AssociatedEnvironmentsSelector } from '../components/AssociatedEnvironmentsSelector/AssociatedEnvironmentsSelector';

export function EditGroupView() {
  const groupId = useIdParam();
  const router = useRouter();
  const queryClient = useQueryClient();
  const groupQuery = useGroup(groupId);
  const isUnassignedGroup = groupId === 1;
  const updateMutation = useUpdateGroupMutation();
  const deleteMutation = useDeleteEnvironmentGroupMutation();

  const initialValues: GroupFormValues = useMemo(
    () => ({
      name: groupQuery.data?.Name ?? '',
      description: groupQuery.data?.Description ?? '',
      tagIds: groupQuery.data?.TagIds ?? [],
    }),
    [groupQuery.data]
  );

  return (
    <>
      <PageHeader
        title="Environment group details"
        breadcrumbs={[
          { label: 'Groups', link: 'portainer.groups' },
          { label: groupQuery.data?.Name ?? 'Edit group' },
        ]}
      >
        <DeleteButton
          disabled={isUnassignedGroup || !groupQuery.data}
          confirmMessage="Are you sure you want to delete this environment group? Environments within it will become unassigned."
          onConfirmed={handleDelete}
          isLoading={deleteMutation.isLoading}
          data-cy="delete-environment-group-button"
        />
      </PageHeader>

      <div className="row">
        <div className="col-sm-12">
          <Widget>
            <Widget.Body loading={groupQuery.isLoading}>
              {groupQuery.isError && (
                <Alert color="error" title="Error">
                  Failed to load group details
                </Alert>
              )}
              {!groupQuery.isError && groupQuery.data && (
                <GroupForm
                  initialValues={initialValues}
                  onSubmit={handleSubmit}
                  submitLabel="Update"
                  submitLoadingLabel="Updating..."
                  groupId={groupId}
                />
              )}
            </Widget.Body>
          </Widget>
        </div>
      </div>

      <div className="row pb-20">
        <div className="col-sm-12">
          <AssociatedEnvironmentsSelector
            groupId={groupId}
            readOnly={isUnassignedGroup}
          />
        </div>
      </div>
    </>
  );

  async function handleDelete() {
    await deleteMutation.mutateAsync(groupId);
    notifySuccess('Success', 'Environment group successfully deleted');
    await router.stateService.go('portainer.groups');
    queryClient.invalidateQueries({ queryKey: queryKeys.base(), exact: true });
  }

  async function handleSubmit(
    values: GroupFormValues,
    { resetForm }: FormikHelpers<GroupFormValues>
  ) {
    await updateMutation.mutateAsync(
      {
        id: groupId,
        name: values.name,
        description: values.description,
        tagIds: values.tagIds,
        // associatedEnvironments omitted — backend preserves existing when field is absent (nil)
      },
      {
        onSuccess() {
          resetForm();
          router.stateService.go('portainer.groups');
        },
      }
    );
  }
}
