import { useState } from 'react';
import { AlertTriangle } from 'lucide-react';

import { EnvironmentId } from '@/react/portainer/environments/types';
import { Stack, StackStatus, StackType } from '@/react/common/stacks/types';
import { Authorized } from '@/react/hooks/useUser';
import { InfoPanel } from '@/react/portainer/gitops/InfoPanel';

import { Icon } from '@@/Icon';
import { Button } from '@@/buttons';
import { FormSection } from '@@/form-components/FormSection';

import { useSwarmStackResources } from '../useSwarmStackServices';
import { useComposeStackContainers } from '../useComposeStackContainers';

import { StackDuplicationForm } from './StackDuplicationForm/StackDuplicationForm';
import { EditGitSettingsModal } from './EditGitSettings/EditGitSettingsModal';
import { StackActions } from './StackActions';
import { AssociateStackForm } from './AssociateStackForm';

interface StackInfoTabProps {
  stack?: Stack; // will be loaded only if regular or orphaned
  stackName: string;
  stackFileContent?: string;
  isRegular?: boolean;
  isExternal: boolean;
  isOrphaned: boolean;
  isOrphanedRunning: boolean;
  environmentId: number;
  yamlError?: string;
}

export function StackInfoTab({
  stack,
  stackName,
  stackFileContent,
  isRegular,
  isExternal,
  isOrphaned,
  isOrphanedRunning,
  environmentId,
  yamlError,
}: StackInfoTabProps) {
  const [isEditOpen, setIsEditOpen] = useState(false);
  const status = useStackStatus({
    status: stack?.Status,
    environmentId,
    name: stackName,
    type: stack?.Type,
  });

  return (
    <>
      <ExternalOrphanedWarning
        isExternal={isExternal}
        isOrphaned={isOrphaned || isOrphanedRunning}
      />

      <FormSection title="Stack details">
        <div className="form-group">
          {stackName}

          {stack && (
            <div className="inline-flex ml-3">
              <StackActions
                stack={stack}
                fileContent={stackFileContent}
                isRegular={isRegular}
                environmentId={environmentId}
                isExternal={isExternal}
                status={status}
              />
            </div>
          )}
        </div>
      </FormSection>

      {stack && (
        <>
          {isOrphaned ? (
            <AssociateStackForm
              stackName={stackName}
              environmentId={environmentId}
              isOrphanedRunning={isOrphanedRunning}
              stackId={stack.Id}
            />
          ) : (
            <>
              {stack.GitConfig && !stack.FromAppTemplate && (
                <>
                  <InfoPanel
                    type="stack"
                    currentDeployment={
                      stack.CurrentDeploymentInfo
                        ? {
                            repositoryUrl:
                              stack.CurrentDeploymentInfo.RepositoryURL ??
                              stack.GitConfig.URL,
                            configFilePath:
                              stack.CurrentDeploymentInfo.ConfigFilePath ??
                              stack.GitConfig.ConfigFilePath,
                            additionalFiles:
                              stack.CurrentDeploymentInfo.AdditionalFiles,
                            commitHash:
                              stack.CurrentDeploymentInfo.ConfigHash ??
                              stack.GitConfig.ConfigHash,
                          }
                        : {
                            repositoryUrl: stack.GitConfig.URL,
                            configFilePath: stack.GitConfig.ConfigFilePath,
                            additionalFiles: stack.AdditionalFiles ?? [],
                            commitHash: stack.GitConfig.ConfigHash,
                          }
                    }
                    nextDeployment={
                      stack.CurrentDeploymentInfo
                        ? {
                            repositoryUrl: stack.GitConfig.URL,
                            configFilePath: stack.GitConfig.ConfigFilePath,
                            additionalFiles: stack.AdditionalFiles ?? [],
                            commitHash: stack.GitConfig.ConfigHash,
                          }
                        : undefined
                    }
                  />
                  <Authorized authorizations="PortainerStackUpdate">
                    <Button
                      size="small"
                      color="default"
                      onClick={() => setIsEditOpen(true)}
                      data-cy="edit-git-settings-button"
                    >
                      Edit Git settings
                    </Button>
                  </Authorized>
                  {isEditOpen && (
                    <EditGitSettingsModal
                      onClose={() => setIsEditOpen(false)}
                      stack={stack}
                    />
                  )}
                </>
              )}

              {isRegular && !!stackFileContent && (
                <StackDuplicationForm
                  yamlError={yamlError}
                  currentEnvironmentId={environmentId}
                  originalFileContent={stackFileContent}
                  stack={stack}
                />
              )}
            </>
          )}
        </>
      )}
    </>
  );
}

function ExternalOrphanedWarning({
  isExternal,
  isOrphaned,
}: {
  isExternal: boolean;
  isOrphaned: boolean;
}) {
  if (!isExternal && !isOrphaned) return null;

  return (
    <FormSection title="Information">
      <div className="form-group">
        <span className="small">
          <p className="text-muted flex items-start gap-1">
            <Icon icon={AlertTriangle} mode="warning" className="!mr-0" />
            {isExternal && (
              <span>
                This stack was created outside of Portainer. Control over this
                stack is limited.
              </span>
            )}
            {isOrphaned && (
              <span>
                This stack is orphaned. You can re-associate it with the current
                environment using the &quot;Associate to this environment&quot;
                feature.
              </span>
            )}
          </p>
        </span>
      </div>
    </FormSection>
  );
}

function useStackStatus({
  status,
  name,
  type,
  environmentId,
}: {
  status: Stack['Status'] | undefined;
  name: string;
  type: Stack['Type'] | undefined;
  environmentId: EnvironmentId;
}) {
  const servicesQuery = useSwarmStackResources(name, {
    enabled: type === StackType.DockerSwarm && !status,
  });
  const containersQuery = useComposeStackContainers(
    { environmentId, stackName: name },
    {
      enabled: type === StackType.DockerCompose && !status,
    }
  );

  const derivedSwarmStatus = servicesQuery.data?.length
    ? StackStatus.Active
    : StackStatus.Inactive;
  const derivedComposeStatus = containersQuery.data?.length
    ? StackStatus.Active
    : StackStatus.Inactive;
  const derivedStatus =
    type === StackType.DockerSwarm ? derivedSwarmStatus : derivedComposeStatus;

  return status || derivedStatus;
}
