import { ChangeEvent, useState } from 'react';
import { RefreshCcw, Loader2, X, Check } from 'lucide-react';

import { useDebounce } from '@/react/hooks/useDebounce';
import { useGitRepoValidity } from '@/react/portainer/gitops/hooks/useGitRepoValidity';

import { FormControl } from '@@/form-components/FormControl';
import { Input } from '@@/form-components/Input';
import { Button } from '@@/buttons';
import { TooltipWithChildren } from '@@/Tip/TooltipWithChildren';

import { isBE } from '../feature-flags/feature-flags.service';

import { GitFormModel } from './types';
import { getAuthentication } from './utils';

interface Props {
  value: string;
  onChange(value: string): void;
  onChangeRepositoryValid(value: boolean): void;
  model: GitFormModel;
  createdFromCustomTemplateId?: number;
  errors?: string;
  placeholder?: string;
}

export function GitFormUrlField({
  value,
  onChange,
  onChangeRepositoryValid,
  model,
  createdFromCustomTemplateId,
  errors,
  placeholder = 'e.g. https://github.com/portainer/portainer-compose',
}: Props) {
  const creds = getAuthentication(model);
  const [force, setForce] = useState(false);
  const { errorMessage, isChecking, isValid, query } = useGitRepoValidity({
    url: value,
    creds,
    force,
    tlsSkipVerify: model.TLSSkipVerify,
    createdFromCustomTemplateId,
    enabled: isBE,
    onSettled: onChangeRepositoryValid,
    onAfterSettle: () => setForce(false),
  });

  const [debouncedValue, debouncedOnChange] = useDebounce(value, onChange);

  const fieldErrorMessage = errorMessage || errors;

  return (
    <div className="form-group">
      <div className="col-sm-12">
        <FormControl
          label="Repository URL"
          inputId="stack_repository_url"
          errors={fieldErrorMessage}
          required
        >
          <span className="flex">
            <div className="relative flex-1">
              <Input
                value={debouncedValue}
                type="text"
                name="repoUrlField"
                className="form-control pr-8"
                placeholder={placeholder}
                data-cy="component-gitUrlInput"
                required
                onChange={handleChange}
                id="stack_repository_url"
              />
              {debouncedValue !== '' && (
                <div className="absolute right-2 top-1/2 flex -translate-y-1/2 transform items-center">
                  {isChecking && (
                    <span
                      className="inline-flex items-center"
                      aria-live="polite"
                      aria-label="Checking repository"
                    >
                      <Loader2
                        className="h-4 w-4 animate-spin stroke-gray-6"
                        aria-hidden="true"
                      />
                    </span>
                  )}
                  {!isChecking && isValid === false && query.isFetched && (
                    <TooltipWithChildren message="Repository does not exist, or is not accessible">
                      <span
                        className="inline-flex items-center"
                        aria-label="Repository does not exist, or is not accessible"
                      >
                        <X
                          className="h-4 w-4 stroke-error-6"
                          aria-hidden="true"
                        />
                      </span>
                    </TooltipWithChildren>
                  )}
                  {!isChecking && isValid === true && (
                    <TooltipWithChildren message="Repository detected">
                      <span
                        className="inline-flex items-center"
                        aria-label="Repository detected"
                      >
                        <Check
                          className="h-4 w-4 stroke-green-6"
                          aria-hidden="true"
                        />
                      </span>
                    </TooltipWithChildren>
                  )}
                </div>
              )}
            </div>

            <Button
              onClick={onRefresh}
              data-cy="component-gitUrlRefreshButton"
              size="medium"
              className="vertical-center"
              color="light"
              icon={RefreshCcw}
              title="Refresh Git Repository"
              aria-label="Refresh Git Repository"
              disabled={!model.RepositoryURLValid}
            />
          </span>
        </FormControl>
      </div>
    </div>
  );

  function handleChange(e: ChangeEvent<HTMLInputElement>) {
    debouncedOnChange(e.target.value);
  }

  function onRefresh() {
    setForce(true);
  }
}
