import { SourceDetail } from '../../queries/useSource';

import { ConnectionDetailsWidget } from './ConnectionDetailsWidget';
import { AuthWidget } from './AuthWidget';
import { AutoUpdateWidget } from './AutoUpdateWidget';
import { SyncStatusWidget } from './SyncStatusWidget';

interface Props {
  source: SourceDetail;
}

export function SettingsTab({ source }: Props) {
  return (
    <>
      <ConnectionDetailsWidget source={source} />
      <AuthWidget auth={source?.connection?.authentication} />
      <AutoUpdateWidget autoUpdate={source.autoUpdate} />
      <SyncStatusWidget source={source} />
    </>
  );
}
