import { LockIcon } from 'lucide-react';

import { Card } from '@@/primitives/Card';
import { Badge } from '@@/Badge';

import { DetailField } from './DetailField';

interface Props {
  auth?: boolean;
}

export function AuthWidget({ auth }: Props) {
  return (
    <Card.Container>
      <Card.Header
        icon={LockIcon}
        title="Authentication"
        subtitle="Credentials used to connect to this source"
      />
      <Card.Body>
        <div className="grid grid-cols-2 gap-4">
          {auth ? (
            <>
              <DetailField label="Authentication Method">
                <Badge type="info" data-cy="source-auth-method">
                  Basic
                </Badge>
              </DetailField>
              <DetailField label="Credentials">
                <span
                  className="font-mono text-sm"
                  data-cy="source-auth-credentials"
                >
                  ********
                </span>
              </DetailField>
            </>
          ) : (
            <DetailField label="Authentication Method">
              <Badge type={'muted'} data-cy="source-auth-method">
                None
              </Badge>
            </DetailField>
          )}
        </div>
      </Card.Body>
    </Card.Container>
  );
}
