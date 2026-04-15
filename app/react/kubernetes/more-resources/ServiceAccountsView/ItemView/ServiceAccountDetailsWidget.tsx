import { Secret } from 'kubernetes-types/core/v1';

import { useEnvironmentId } from '@/react/hooks/useEnvironmentId';
import { useCurrentUser } from '@/react/hooks/useUser';
import { useSecrets } from '@/react/kubernetes/configs/queries/useSecrets';
import { useRegistry } from '@/react/portainer/registries/queries/useRegistry';

import { Badge } from '@@/Badge';
import { SystemBadge } from '@@/Badge/SystemBadge';
import { DetailsRow } from '@@/DetailsTable/DetailsRow';
import { DetailsTable } from '@@/DetailsTable/DetailsTable';
import { Link } from '@@/Link';
import { Tooltip } from '@@/Tip/Tooltip';
import { Widget, WidgetBody } from '@@/Widget';
import { TooltipWithChildren } from '@@/Tip/TooltipWithChildren';

import { useServiceAccount } from '../queries/useServiceAccount';

type Props = { namespace: string; name: string };

export function ServiceAccountDetailsWidget({ namespace, name }: Props) {
  const environmentId = useEnvironmentId();
  const serviceAccountQuery = useServiceAccount(environmentId, namespace, name);
  const { data: serviceAccount } = serviceAccountQuery;
  const { isLoading } = serviceAccountQuery;

  return (
    <div className="row">
      <div className="col-sm-12">
        <Widget>
          <WidgetBody loading={isLoading}>
            <DetailsTable
              dataCy="k8sSADetail-table"
              className="[&_td:first-child]:w-2/5"
            >
              <DetailsRow label="Name">
                {serviceAccount?.name}
                {serviceAccount?.isSystem && <SystemBadge className="ml-1" />}
              </DetailsRow>
              <DetailsRow label="Namespace">
                <Link
                  to="kubernetes.resourcePools.resourcePool"
                  params={{ id: namespace }}
                  data-cy="namespace-link"
                >
                  {namespace}
                </Link>
                {serviceAccount?.isSystem && <SystemBadge className="ml-1" />}
              </DetailsRow>
              <DetailsRow label="Creation date">
                {serviceAccount?.creationDate
                  ? new Date(serviceAccount.creationDate).toLocaleString()
                  : '-'}
              </DetailsRow>
              <DetailsRow
                label={
                  <>
                    Automount token
                    <Tooltip message="Controls whether pods automatically receive an API token for cluster access. Disabling this reduces attack surface for workloads that don't need Kubernetes API access. Individual pods can still override this setting." />
                  </>
                }
              >
                <span className="flex items-center">
                  {serviceAccount?.automountServiceAccountToken === false
                    ? 'Disabled'
                    : 'Enabled'}
                </span>
              </DetailsRow>

              <ImagePullSecretsRow
                namespace={namespace}
                name={name}
                imagePullSecrets={serviceAccount?.imagePullSecrets ?? []}
              />
            </DetailsTable>
          </WidgetBody>
        </Widget>
      </div>
    </div>
  );
}

const MAX_VISIBLE_SECRETS = 5;

type ImagePullSecretName = { name: string };

type ImagePullSecretsRowProps = {
  namespace: string;
  name: string;
  imagePullSecrets: ImagePullSecretName[];
};

function ImagePullSecretsRow({
  namespace,
  name,
  imagePullSecrets,
}: ImagePullSecretsRowProps) {
  const environmentId = useEnvironmentId();
  const { data: secrets = [] } = useSecrets(environmentId, namespace);

  const pullSecretNamesToSecrets = linkImagePullSecretsToSecrets(
    secrets,
    imagePullSecrets
  );

  const visibleSecrets = pullSecretNamesToSecrets.slice(0, MAX_VISIBLE_SECRETS);
  const hiddenSecrets = pullSecretNamesToSecrets.slice(MAX_VISIBLE_SECRETS);

  return (
    <DetailsRow
      label={
        <span className="flex items-center">
          Image pull secrets
          <Tooltip
            message={
              name === 'default' ? (
                <>
                  <code>imagePullSecrets</code> from this &apos;default&apos;
                  service account apply to all <strong>pods</strong> without an
                  explicit service account in this namespace.
                </>
              ) : (
                <>
                  These <code>imagePullSecrets</code> are inherited by pods
                  using this service account.
                </>
              )
            }
          />
        </span>
      }
    >
      <div className="mt-2 flex flex-col">
        {visibleSecrets.length > 0 ? (
          <div className="flex flex-wrap gap-1">
            {visibleSecrets.map((s) => (
              <ImagePullSecretBadge
                key={s.name}
                secretName={s.name}
                namespace={namespace}
                secret={s.secret}
              />
            ))}
            {hiddenSecrets.length > 0 && (
              <TooltipWithChildren
                message={hiddenSecrets.map((s) => s.name).join(', ')}
              >
                <span>
                  <Badge type="muted" className="min-w-max cursor-default">
                    + {hiddenSecrets.length} more
                  </Badge>
                </span>
              </TooltipWithChildren>
            )}
          </div>
        ) : (
          <span className="text-muted">None</span>
        )}
      </div>
    </DetailsRow>
  );
}

function linkImagePullSecretsToSecrets(
  secrets: Secret[],
  secretNames: { name: string }[]
) {
  return secretNames.map(({ name }) => {
    const secret = secrets.find((s) => s.metadata?.name === name);
    return { name, secret };
  });
}

type ImagePullSecretBadgeProps = {
  secretName: string;
  namespace: string;
  secret: Secret | undefined;
};

function ImagePullSecretBadge({
  secretName,
  namespace,
  secret,
}: ImagePullSecretBadgeProps) {
  const { isPureAdmin } = useCurrentUser();
  const registryIdStr =
    secret?.metadata?.annotations?.['portainer.io/registry.id'];
  const registryId = registryIdStr
    ? parseInt(registryIdStr, 10) || undefined
    : undefined;
  const { data: registry, isLoading: isRegistryLoading } =
    useRegistry(registryId);

  const registryTooltip = registry && (
    <Tooltip
      position="right"
      message={
        <div className="flex flex-col gap-1">
          <span>
            <span className="font-medium">Registry: </span>
            {isPureAdmin ? (
              <Link
                to="portainer.registries.registry"
                params={{ id: registry.Id }}
                className="!text-inherit underline"
                data-cy={`registry-link-${registry.Id}`}
                rel="noopener noreferrer"
                target="_blank"
              >
                {registry.Name}
              </Link>
            ) : (
              registry.Name
            )}
          </span>
          <span>
            <span className="font-medium">URL: </span>
            {registry.URL}
          </span>
        </div>
      }
    />
  );

  const registryNotFoundMessage =
    'The registry associated with this secret could not be found. It may have been deleted.';
  const showRegistryNotFound = !!registryId && !isRegistryLoading && !registry;

  const secretLink = (
    <Link
      to="kubernetes.secrets.secret"
      params={{ name: secretName, namespace }}
      data-cy={`image-pull-secret-link-${secretName}`}
      className="!text-inherit"
    >
      {secretName}
    </Link>
  );

  const missingSecretContent = (
    <>
      {secretName}
      <Tooltip message="This secret doesn't exist in the namespace." />
    </>
  );

  function renderSecretName() {
    const content = secret ? secretLink : missingSecretContent;
    if (showRegistryNotFound) {
      return (
        <TooltipWithChildren message={registryNotFoundMessage}>
          <span>{content}</span>
        </TooltipWithChildren>
      );
    }
    return content;
  }

  return (
    <Badge
      type={secret ? 'info' : 'warn'}
      className="inline-flex min-w-max items-center"
    >
      {renderSecretName()}
      {registryTooltip}
    </Badge>
  );
}
