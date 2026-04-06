import { useState } from 'react';
import { Formik } from 'formik';

import { Stack, StackType } from '@/react/common/stacks/types';
import { toGitFormModel } from '@/react/portainer/gitops/types';
import {
  parseAutoUpdateResponse,
  transformAutoUpdateViewModel,
} from '@/react/portainer/gitops/AutoUpdateFieldset/utils';
import { createWebhookId } from '@/portainer/helpers/webhookHelper';
import { notifyError, notifySuccess } from '@/portainer/services/notifications';
import { confirmStackUpdate } from '@/react/common/stacks/common/confirm-stack-update';

import { useUpdateGitStack } from './useUpdateGitStack';
import { FormValues } from './types';
import { InnerForm } from './InnerForm';
import { useValidationSchema } from './validation';

interface Props {
  onClose: () => void;
  stack: Stack;
}

export function EditGitSettingsModal({ stack, onClose }: Props) {
  const [webhookId] = useState(
    () => stack.AutoUpdate?.Webhook || createWebhookId()
  );

  const gitModel = toGitFormModel(
    stack.GitConfig,
    parseAutoUpdateResponse(stack.AutoUpdate)
  );

  const initialValues: FormValues = {
    git: {
      ...gitModel,
      AdditionalFiles: stack.AdditionalFiles || [],
    },
    env: stack.Env || [],
    prune: stack.Option?.Prune || false,
    redeployNow: false,
  };

  const mutation = useUpdateGitStack(stack);
  const validationSchema = useValidationSchema(stack.Type);

  return (
    <Formik
      initialValues={initialValues}
      validationSchema={validationSchema}
      onSubmit={handleSubmit}
    >
      <InnerForm
        stackName={stack.Name}
        stackType={stack.Type}
        webhookId={webhookId}
        onDismiss={onClose}
        isSubmitting={mutation.isLoading}
      />
    </Formik>
  );

  async function handleSubmit(values: FormValues) {
    let repullImageAndRedeploy: boolean | undefined;
    if (values.redeployNow) {
      const result = await confirmStackUpdate(
        'Any changes to this stack or application made locally in Portainer will be overridden, which may cause service interruption. Do you wish to continue?',
        stack.Type === StackType.DockerSwarm
      );
      if (!result) {
        return;
      }
      repullImageAndRedeploy = result.repullImageAndRedeploy;
    }

    const autoUpdate = transformAutoUpdateViewModel(
      values.git.AutoUpdate,
      webhookId
    );

    mutation.mutate(
      {
        payload: {
          RepositoryURL: values.git.RepositoryURL,
          ConfigFilePath: values.git.ComposeFilePathInRepository,
          RepositoryReferenceName: values.git.RepositoryReferenceName,
          RepositoryAuthentication: values.git.RepositoryAuthentication,
          RepositoryGitCredentialID: values.git.RepositoryGitCredentialID,
          RepositoryUsername: values.git.RepositoryUsername,
          RepositoryPassword: values.git.RepositoryPassword,
          RepositoryAuthorizationType: values.git.RepositoryAuthorizationType,
          TLSSkipVerify: values.git.TLSSkipVerify,
          AutoUpdate: autoUpdate,
          AdditionalFiles: values.git.AdditionalFiles,
          env: values.env,
          prune: values.prune,
        },
        repullImageAndRedeploy,
      },
      {
        onError(err) {
          notifyError('Failure', err as Error, 'Unable to save stack settings');
        },
        onSuccess({ redeployAttempted, redeployFailed, redeployError }) {
          if (redeployFailed) {
            notifyError(
              'Failure',
              redeployError as Error,
              'Stack settings saved but redeploy failed'
            );
          } else if (redeployAttempted) {
            notifySuccess('Success', 'Stack deployed successfully');
          } else {
            notifySuccess('Success', 'Stack settings saved successfully');
          }
          onClose();
        },
      }
    );
  }
}
