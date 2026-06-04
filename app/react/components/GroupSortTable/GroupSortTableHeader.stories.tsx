import { Meta } from '@storybook/react-webpack5';
import { useState } from 'react';
import { expect, within } from 'storybook/test';
import { Server, Cloud, Code } from 'lucide-react';

import { Icon } from '@@/Icon';

import { GroupSortTableHeader, SortOption } from './GroupSortTableHeader';

export default {
  component: GroupSortTableHeader,
  title: 'Components/Tables/GroupSortTableHeader',
} as Meta;

const availableGroups = [
  { key: 'Production', count: 12, icon: <Icon icon={Server} /> },
  { key: 'Staging', count: 5, icon: <Icon icon={Cloud} /> },
  { key: 'Development', count: 8, icon: <Icon icon={Code} /> },
];

export function Interactive() {
  const [sortBy, setSortBy] = useState('name');
  const [searchTerm, setSearchTerm] = useState('');
  const [groupFilter, setGroupFilter] = useState<string | null>(null);

  const sortOptions: SortOption<string>[] = [
    { key: 'name', label: 'Name' },
    {
      key: 'group',
      label: 'Group',
      dropdown: {
        options: availableGroups,
        selected: groupFilter,
        onSelect: setGroupFilter,
      },
    },
    { key: 'status', label: 'Status' },
  ];

  return (
    <GroupSortTableHeader
      sortBy={sortBy}
      onSortChange={setSortBy}
      searchTerm={searchTerm}
      onSearchChange={setSearchTerm}
      sortOptions={sortOptions}
      searchPlaceholder="Search environments..."
      searchDataCy="group-sort-search"
    />
  );
}

export function MixedButtonTypes() {
  const [sortBy, setSortBy] = useState('Name');
  const [searchTerm, setSearchTerm] = useState('');
  const [platformFilter, setPlatformFilter] = useState<string | null>(null);
  const [govFilter, setGovFilter] = useState<string | null>(null);

  const sortOptions: SortOption<string>[] = [
    { key: 'Name', label: 'Name' },
    {
      key: 'Platform',
      label: 'Platform',
      dropdown: {
        options: [
          { key: 'Docker', count: 5 },
          { key: 'Kubernetes', count: 3 },
          { key: 'Podman', count: 1 },
        ],
        selected: platformFilter,
        onSelect: setPlatformFilter,
      },
    },
    {
      key: 'Governance',
      label: 'Governance',
      dropdown: {
        options: [
          { key: 'Ungoverned', count: 2 },
          { key: 'Policy Attached', count: 7 },
        ],
        selected: govFilter,
        onSelect: setGovFilter,
      },
    },
  ];

  return (
    <div className="flex flex-col gap-4">
      <GroupSortTableHeader
        sortBy={sortBy}
        onSortChange={setSortBy}
        searchTerm={searchTerm}
        onSearchChange={setSearchTerm}
        sortOptions={sortOptions}
        searchPlaceholder="Filter groups..."
        actionButton={
          <button
            type="button"
            className="rounded bg-blue-8 px-3 py-1.5 text-sm text-white"
          >
            Add Group
          </button>
        }
      />
      <div className="p-4 text-sm">
        Sort: <strong>{sortBy}</strong> | Platform:{' '}
        <strong>{platformFilter ?? 'All'}</strong> | Governance:{' '}
        <strong>{govFilter ?? 'All'}</strong>
      </div>
    </div>
  );
}

export function MultipleBadgesPersist() {
  const [sortBy, setSortBy] = useState('Governance');
  const [searchTerm, setSearchTerm] = useState('');

  const sortOptions: SortOption<string>[] = [
    { key: 'Name', label: 'Name' },
    {
      key: 'Platform',
      label: 'Platform',
      dropdown: {
        options: [{ key: 'Docker', count: 5 }],
        selected: 'Docker',
        onSelect: () => {},
      },
    },
    {
      key: 'Governance',
      label: 'Governance',
      dropdown: {
        options: [{ key: 'Ungoverned', count: 2 }],
        selected: 'Ungoverned',
        onSelect: () => {},
      },
    },
  ];

  return (
    <GroupSortTableHeader
      sortBy={sortBy}
      onSortChange={setSortBy}
      searchTerm={searchTerm}
      onSearchChange={setSearchTerm}
      sortOptions={sortOptions}
    />
  );
}

MultipleBadgesPersist.play = async ({
  canvasElement,
}: {
  canvasElement: HTMLElement;
}) => {
  const canvas = within(canvasElement);

  // Governance is the active sort — its badge should show
  const govBtn = canvas.getByRole('button', { name: /Governance/i });
  await expect(govBtn).toHaveTextContent('Ungoverned');

  // Platform is inactive — its badge should ALSO show
  const platformBtn = canvas.getByRole('button', { name: /Platform/i });
  await expect(platformBtn).toHaveTextContent('Docker');
};
