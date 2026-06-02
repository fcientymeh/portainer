import { EnvironmentGroup } from '../types';
import { getPlatformLabel } from '../utils/getPlatformLabel';

const colorByLabel: Record<string, string> = {
  Docker: 'bg-green-2',
  Kubernetes: 'bg-blue-2',
  Podman: 'bg-orange-2',
  Mixed: 'bg-purple-2',
  Empty: 'bg-gray-2',
};

interface Props {
  group: EnvironmentGroup;
}

export function PlatformBadge({ group }: Props) {
  const platformLabel = getPlatformLabel(group);
  const colorClass = colorByLabel[platformLabel] ?? 'bg-gray-2';

  return (
    <span
      className={`flex w-fit items-center rounded-xl ${colorClass} px-2 py-px text-xs font-bold text-gray-9 th-highcontrast:bg-gray-8 th-highcontrast:text-white th-dark:bg-gray-8 th-dark:text-gray-3`}
      data-cy={`environment-group-platform_${group.Name}`}
    >
      {platformLabel}
    </span>
  );
}
