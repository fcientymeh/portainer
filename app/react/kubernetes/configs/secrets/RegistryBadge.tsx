import { useCurrentUser } from '@/react/hooks/useUser';
import { useRegistry } from '@/react/portainer/registries/queries/useRegistry';

import { Badge } from '@@/Badge';
import { Link } from '@@/Link';
import { InlineLoader } from '@@/InlineLoader/InlineLoader';

type Props = {
  registryId: number;
  children?: React.ReactNode;
  dataCy?: string;
};

export function RegistryBadge({ registryId, children, dataCy }: Props) {
  const registryQuery = useRegistry(registryId);
  const { isPureAdmin } = useCurrentUser();

  if (registryQuery.isLoading) {
    return <InlineLoader>Loading registry...</InlineLoader>;
  }

  if (registryQuery.isError || !registryQuery.data) {
    return <Badge type="warn">Registry deleted</Badge>;
  }

  const { Name } = registryQuery.data;

  return (
    <Badge type="muted" data-cy={dataCy}>
      {isPureAdmin ? (
        <Link
          to="portainer.registries.registry"
          params={{ id: registryId }}
          className="!text-inherit"
          data-cy={dataCy ? `${dataCy}-link` : undefined}
        >
          {Name}
        </Link>
      ) : (
        Name
      )}
      {children}
    </Badge>
  );
}
