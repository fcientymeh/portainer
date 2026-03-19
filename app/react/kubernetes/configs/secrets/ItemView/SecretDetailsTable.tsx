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
    </DetailsTable>
  );
}
