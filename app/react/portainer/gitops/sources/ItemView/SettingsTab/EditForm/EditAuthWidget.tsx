import { LockIcon } from 'lucide-react';
import { useFormikContext } from 'formik';

import { Card } from '@@/primitives/Card';
import { SwitchField } from '@@/form-components/SwitchField';
import { FormControl } from '@@/form-components/FormControl';
import { Input } from '@@/form-components/Input';

import { SettingsFormValues } from './types';

export function EditAuthWidget() {
  const { values, errors, setFieldValue } =
    useFormikContext<SettingsFormValues>();

  return (
    <Card.Container>
      <Card.Header
        icon={LockIcon}
        title="Authentication"
        subtitle="Choose how Portainer authenticates to this source"
      />
      <Card.Body>
        <div className="mb-3">
          <SwitchField
            label="Authentication"
            name="authEnabled"
            checked={values.authEnabled}
            onChange={(checked) => setFieldValue('authEnabled', checked)}
            data-cy="source-auth-enabled"
          />
        </div>

        {values.authEnabled && (
          <>
            <FormControl label="Username" errors={errors?.username}>
              <Input
                value={values.username}
                name="repository_username"
                placeholder="git username"
                onChange={(e) => setFieldValue('username', e.target.value)}
                data-cy="component-gitUsernameInput"
              />
            </FormControl>

            <FormControl
              label="Personal Access Token"
              tooltip="Provide a personal access token or password"
              errors={errors?.password}
            >
              <Input
                type="password"
                value={values.password}
                name="repository_password"
                placeholder="*******"
                onChange={(e) => setFieldValue('password', e.target.value)}
                data-cy="component-gitPasswordInput"
              />
            </FormControl>
          </>
        )}
      </Card.Body>
    </Card.Container>
  );
}
