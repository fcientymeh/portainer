import { useEnvironmentId } from '@/react/hooks/useEnvironmentId';
import { useGetAllServiceAccountsQuery } from '@/react/kubernetes/more-resources/ServiceAccountsView/ServiceAccountsDatatable/queries/useGetAllServiceAccountsQuery';

import { Badge } from '@@/Badge';
import { SystemBadge } from '@@/Badge/SystemBadge';
import { DetailsRow } from '@@/DetailsTable/DetailsRow';
import { DetailsTable } from '@@/DetailsTable/DetailsTable';
import { Link } from '@@/Link';
import { Tooltip } from '@@/Tip/Tooltip';

import { RegistryBadge } from '../RegistryBadge';

type Props = {
  name: string;
  namespace: string;
  secretTypeLabel: string;
  // Passed from Angular as ctrl.isSystemNamespace() — true when the namespace is a system namespace
  isSystem: boolean;
  // Angular passes annotation values as strings; accept both and parse internally
  registryId?: number | string;
};

export function SecretDetailsTable({
  name,
  namespace,
  secretTypeLabel,
  isSystem,
  registryId,
}: Props) {
  const parsedRegistryId =
    registryId !== undefined && registryId !== ''
      ? parseInt(String(registryId), 10) || undefined
      : undefined;

  return (
    <DetailsTable
      dataCy="k8sConfigDetail-configTable"
      className="[&_td:first-child]:w-2/5"
    >
      <DetailsRow label="Name">
        {name} {isSystem && <SystemBadge />}
      </DetailsRow>
      <DetailsRow label="Namespace">
        <Link
          to="kubernetes.resourcePools.resourcePool"
          params={{ id: namespace }}
          data-cy={`namespace-link-${namespace}`}
        >
          {namespace}
        </Link>{' '}
        {isSystem && <SystemBadge />}
      </DetailsRow>
      {secretTypeLabel && (
        <DetailsRow label="Secret Type">{secretTypeLabel}</DetailsRow>
      )}
      {parsedRegistryId && (
        <DetailsRow label="Registry">
          <RegistryBadge registryId={parsedRegistryId}>
            <Tooltip message="This registry secret was created by Portainer to allow pulling images. Manually editing this secret is disabled." />
          </RegistryBadge>
        </DetailsRow>
      )}
      <LinkedServiceAccountsRow secretName={name} namespace={namespace} />
    </DetailsTable>
  );
}

const MAX_VISIBLE_SERVICE_ACCOUNTS = 5;

type LinkedServiceAccountsRowProps = {
  secretName: string;
  namespace: string;
};

function LinkedServiceAccountsRow({
  secretName,
  namespace,
}: LinkedServiceAccountsRowProps) {
  const environmentId = useEnvironmentId();
  const { data: allServiceAccounts = [] } =
    useGetAllServiceAccountsQuery(environmentId);

  const linked = allServiceAccounts.filter(
    (sa) =>
      sa.namespace === namespace &&
      sa.imagePullSecrets?.some((s) => s.name === secretName)
  );

  const visible = linked.slice(0, MAX_VISIBLE_SERVICE_ACCOUNTS);
  const hidden = linked.slice(MAX_VISIBLE_SERVICE_ACCOUNTS);

  return (
    <DetailsRow
      label={
        <span className="flex items-center">
          Linked service accounts
          <Tooltip message="Service accounts that use this secret as an image pull secret." />
        </span>
      }
    >
      <div className="flex flex-wrap gap-2">
        {visible.length > 0 ? (
          <>
            {visible.map((sa) => (
              <Badge key={sa.uid} type="info" className="min-w-max">
                <Link
                  to="kubernetes.moreResources.serviceAccounts.serviceAccount"
                  params={{ namespace: sa.namespace, name: sa.name }}
                  data-cy={`linked-service-account-link-${sa.name}`}
                  className="!text-inherit"
                >
                  {sa.name}
                </Link>
              </Badge>
            ))}
            {hidden.length > 0 && (
              <Badge type="muted" className="min-w-max cursor-default">
                + {hidden.length} more
              </Badge>
            )}
          </>
        ) : (
          <span className="text-muted">
            None - Link{' '}
            <Link
              to="kubernetes.moreResources.serviceAccounts"
              data-cy="service-account-link"
            >
              service accounts
            </Link>{' '}
            to this secret by referencing it in the{' '}
            <code>imagePullSecrets</code> field in the service account spec.
          </span>
        )}
      </div>
    </DetailsRow>
  );
}
