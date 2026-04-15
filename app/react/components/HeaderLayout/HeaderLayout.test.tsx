import { render, screen } from '@testing-library/react';

import { HeaderLayout } from './HeaderLayout';

function renderComponent(
  props: Partial<React.ComponentProps<typeof HeaderLayout>> = {}
) {
  const defaultProps: React.ComponentProps<typeof HeaderLayout> = {
    isLoading: false,
    title: 'Test Group',
    icon: <span data-cy="test-icon">icon</span>,
    ...props,
  };

  return render(<HeaderLayout {...defaultProps} />);
}

describe('HeaderLayout', () => {
  it('should render title and icon', () => {
    renderComponent();

    expect(screen.getByText('Test Group')).toBeVisible();
    expect(screen.getByTestId('test-icon')).toBeVisible();
  });

  it('should render subtitle when provided', () => {
    renderComponent({ subtitleLabel: 'Environment Group' });

    expect(screen.getByText('Environment Group')).toBeVisible();
  });

  it('should render description when provided', () => {
    renderComponent({ description: 'A test description' });

    expect(screen.getByText('A test description')).toBeVisible();
  });

  it('should render badge when provided', () => {
    renderComponent({ badge: <span>Multi-platform</span> });

    expect(screen.getByText('Multi-platform')).toBeVisible();
  });

  it('should render rightInfo when provided', () => {
    renderComponent({ rightInfo: <span>5 environments</span> });

    expect(screen.getByText('5 environments')).toBeVisible();
  });

  it('should show loading state', () => {
    renderComponent({ isLoading: true });

    expect(screen.getByText('Loading details...')).toBeVisible();
    expect(screen.queryByText('Test Group')).not.toBeInTheDocument();
  });

  it('should show error state', () => {
    renderComponent({ errorMessage: 'Something went wrong' });

    expect(screen.getByText('Something went wrong')).toBeVisible();
    expect(screen.queryByText('Test Group')).not.toBeInTheDocument();
  });
});
