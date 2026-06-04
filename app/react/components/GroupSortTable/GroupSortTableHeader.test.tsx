import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';

import { GroupSortTableHeader, SortOption } from './GroupSortTableHeader';

const defaultGroups = [
  { key: 'Docker', count: 3 },
  { key: 'Kubernetes', count: 2 },
];

const defaultSortOptions: SortOption<string>[] = [
  { key: 'Name', label: 'Name' },
  {
    key: 'Platform',
    label: 'Platform',
    dropdown: {
      options: defaultGroups,
      selected: null,
      onSelect: vi.fn(),
    },
  },
  { key: 'Health', label: 'Health' },
];

function renderHeader(
  overrides: Partial<
    React.ComponentProps<typeof GroupSortTableHeader<string>>
  > = {}
) {
  const props = {
    sortBy: 'Name' as string,
    onSortChange: vi.fn(),
    searchTerm: '',
    onSearchChange: vi.fn(),
    sortOptions: defaultSortOptions,
    ...overrides,
  };

  return {
    ...render(<GroupSortTableHeader {...props} />),
    props,
  };
}

describe('GroupSortTableHeader', () => {
  test('renders all sort option buttons', () => {
    renderHeader();

    expect(screen.getByRole('button', { name: /Name/i })).toBeInTheDocument();
    expect(
      screen.getByRole('button', { name: /Platform/i })
    ).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /Health/i })).toBeInTheDocument();
  });

  test('plain button calls onSortChange when clicked', async () => {
    const user = userEvent.setup();
    const onSortChange = vi.fn();
    renderHeader({ sortBy: 'Platform', onSortChange });

    await user.click(screen.getByRole('button', { name: /^Name$/i }));

    expect(onSortChange).toHaveBeenCalledWith('Name');
  });

  test('dropdown button opens menu with options', async () => {
    const user = userEvent.setup();
    renderHeader({ sortBy: 'Platform' });

    await user.click(screen.getByRole('button', { name: /Platform/i }));

    expect(screen.getByRole('menuitem', { name: /All/ })).toBeVisible();
    expect(screen.getByRole('menuitem', { name: /Docker/ })).toBeVisible();
    expect(screen.getByRole('menuitem', { name: /Kubernetes/ })).toBeVisible();
  });

  test('clicking dropdown button does not change the active sort', async () => {
    const user = userEvent.setup();
    const onSortChange = vi.fn();
    renderHeader({ sortBy: 'Name', onSortChange });

    await user.click(screen.getByRole('button', { name: /Platform/i }));

    expect(onSortChange).not.toHaveBeenCalled();
  });

  test('active dropdown filter is shown as a badge', () => {
    const options: SortOption<string>[] = [
      {
        key: 'Platform',
        label: 'Platform',
        dropdown: {
          options: defaultGroups,
          selected: 'Docker',
          onSelect: vi.fn(),
        },
      },
    ];
    renderHeader({ sortBy: 'Platform', sortOptions: options });

    const btn = screen.getByRole('button', { name: /Platform/i });
    expect(btn).toHaveTextContent('Docker');
  });

  test('dropdown shows counts for each option', async () => {
    const user = userEvent.setup();
    renderHeader({ sortBy: 'Platform' });

    await user.click(screen.getByRole('button', { name: /Platform/i }));

    const menu = screen.getByRole('menu', { name: /Platform/i });
    expect(menu).toHaveTextContent('3');
    expect(menu).toHaveTextContent('2');
  });

  test('search input renders with the correct placeholder', () => {
    renderHeader();

    expect(screen.getByPlaceholderText('Filter...')).toBeInTheDocument();
  });

  test('renders custom search placeholder', () => {
    renderHeader({ searchPlaceholder: 'Search environments...' });

    expect(
      screen.getByPlaceholderText('Search environments...')
    ).toBeInTheDocument();
  });

  test('renders action button when provided', () => {
    renderHeader({
      actionButton: <button type="button">Add item</button>,
    });

    expect(
      screen.getByRole('button', { name: /Add item/i })
    ).toBeInTheDocument();
  });

  test('shows ascending arrow on active sort button when sortAsc is true', () => {
    renderHeader({ sortBy: 'Name', sortAsc: true });

    const activeBtn = screen.getByRole('button', { name: /^Name$/i });
    expect(
      activeBtn.querySelector('.lucide-arrow-down-a-z')
    ).toBeInTheDocument();
    expect(
      activeBtn.querySelector('.lucide-arrow-down-z-a')
    ).not.toBeInTheDocument();
  });

  test('shows descending arrow on active sort button when sortAsc is false', () => {
    renderHeader({ sortBy: 'Name', sortAsc: false });

    const activeBtn = screen.getByRole('button', { name: /^Name$/i });
    expect(
      activeBtn.querySelector('.lucide-arrow-down-z-a')
    ).toBeInTheDocument();
    expect(
      activeBtn.querySelector('.lucide-arrow-down-a-z')
    ).not.toBeInTheDocument();
  });

  test('defaults to ascending arrow on active sort button when sortAsc is undefined', () => {
    renderHeader({ sortBy: 'Name' });

    const activeBtn = screen.getByRole('button', { name: /^Name$/i });
    expect(
      activeBtn.querySelector('.lucide-arrow-down-a-z')
    ).toBeInTheDocument();
    expect(
      activeBtn.querySelector('.lucide-arrow-down-z-a')
    ).not.toBeInTheDocument();
  });

  test('does not show sort direction arrow on inactive sort buttons', () => {
    renderHeader({ sortBy: 'Name', sortAsc: true });

    const inactiveBtn = screen.getByRole('button', { name: /^Health$/i });
    expect(
      inactiveBtn.querySelector('.lucide-arrow-down-a-z')
    ).not.toBeInTheDocument();
    expect(
      inactiveBtn.querySelector('.lucide-arrow-down-z-a')
    ).not.toBeInTheDocument();
  });

  test('does not render clear button when onClear is not provided', () => {
    renderHeader();

    expect(
      screen.queryByRole('button', { name: /Clear all sort options/i })
    ).not.toBeInTheDocument();
  });

  test('renders clear button and calls onClear when clicked', async () => {
    const user = userEvent.setup();
    const onClear = vi.fn();
    renderHeader({ onClear });

    const clearBtn = screen.getByRole('button', {
      name: /Clear all sort options/i,
    });
    expect(clearBtn).toBeInTheDocument();

    await user.click(clearBtn);

    expect(onClear).toHaveBeenCalledTimes(1);
  });
});
