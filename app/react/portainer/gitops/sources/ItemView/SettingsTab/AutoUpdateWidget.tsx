import { RefreshCwIcon } from 'lucide-react';

import { Card } from '@@/primitives/Card';

import { AutoUpdateInfo } from '../../queries/useSource';

import { DetailField } from './DetailField';

interface Props {
  autoUpdate?: AutoUpdateInfo;
}

export function AutoUpdateWidget({ autoUpdate }: Props) {
  const mechanism = autoUpdate?.mechanism ?? '-';
  const fetchInterval = autoUpdate?.fetchInterval ?? '-';

  return (
    <Card.Container>
      <Card.Header
        icon={RefreshCwIcon}
        title="Change Detection"
        subtitle="How Portainer detects new commits"
      />
      <Card.Body>
        <div className="grid grid-cols-2 gap-4">
          <DetailField label="Mechanism">
            <span className="text-gray-6 th-dark:text-gray-5">{mechanism}</span>
          </DetailField>
          <DetailField label="Fetch Interval">
            <span className="text-gray-6 th-dark:text-gray-5">
              {fetchInterval}
            </span>
          </DetailField>
        </div>
      </Card.Body>
    </Card.Container>
  );
}
