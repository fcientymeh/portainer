import { useFormikContext } from 'formik';

import { Input } from '@@/form-components/Input';
import { FormControl } from '@@/form-components/FormControl';
import { SwitchField } from '@@/form-components/SwitchField';

import { FormValues } from '../type';

import { Authentication } from './Authentication';
import { ConnectionTest } from './ConnectionTest';

export function ConfigureGit() {
  const { values, setFieldValue, errors } = useFormikContext<FormValues>();

  if (values.type !== 'git') {
    return null;
  }

  return (
    <div className="grid">
      <FormControl
        inputId="repository-url-input"
        label="Repository URL"
        required
        errors={errors.git?.url}
        tooltip="Enter the full URL of your git repository"
      >
        <Input
          id="repository-url-input"
          value={values.git.url}
          data-cy="repository-url-input"
          placeholder="https://github.com/org/repo"
          required
          onChange={({ target: { value } }) => setFieldValue('git.url', value)}
        />
      </FormControl>

      <SwitchField
        label="Skip TLS Verification"
        labelClass="col-sm-3 col-lg-2"
        name="TLSSkipVerify"
        checked={values.git.tlsSkipVerify || false}
        onChange={(value) => setFieldValue('git.tlsSkipVerify', value)}
        tooltip="Enabling this will allow skipping TLS validation for any self-signed certificate."
        data-cy="tls-skip-verify"
      />

      <Authentication />

      <ConnectionTest />
    </div>
  );
}
