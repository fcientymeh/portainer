import { Meta, StoryObj } from '@storybook/react';
import { Layers, AlertCircle, Database } from 'lucide-react';

import { HeaderLayout } from './HeaderLayout';

const meta: Meta<typeof HeaderLayout> = {
  title: 'Design System/HeaderLayout',
  component: HeaderLayout,
  tags: ['autodocs'],
};

export default meta;
type Story = StoryObj<typeof HeaderLayout>;

export const Default: Story = {
  args: {
    isLoading: false,
    title: 'Production Cluster',
    icon: <Layers className="text-blue-9 th-dark:text-blue-3" />,
    iconBackgroundClassName: 'bg-blue-3 th-dark:bg-blue-9',
    subtitleLabel: 'Environment Group',
    description: 'Main production environment group',
  },
};

export const WithBadge: Story = {
  args: {
    ...Default.args,
    badge: (
      <span className="inline-block rounded-full bg-blue-1 px-2 py-1 text-xs font-medium text-blue-9 th-dark:bg-blue-11 th-dark:text-blue-2">
        Multi-platform
      </span>
    ),
  },
};

export const MinimalUsage: Story = {
  args: {
    isLoading: false,
    title: 'Simple Group',
    icon: <Layers className="text-blue-8" />,
  },
};

export const LoadingState: Story = {
  args: {
    isLoading: true,
    title: 'Loading...',
    icon: <Layers />,
  },
};

export const ErrorState: Story = {
  args: {
    isLoading: false,
    errorMessage: 'Failed to load group details',
    title: '',
    icon: <AlertCircle />,
  },
};

export const CustomIconBackground: Story = {
  args: {
    ...Default.args,
    icon: <Database className="text-warning-8 th-dark:text-warning-2" />,
    iconBackgroundClassName: 'bg-warning-3 th-dark:bg-warning-10',
  },
};

export const LongTitle: Story = {
  args: {
    ...Default.args,
    title:
      'Very Long Environment Group Name That Might Wrap to Multiple Lines in Some Contexts',
    description:
      'This group contains multiple types of container engines including Docker, Kubernetes, and Podman installations',
  },
};
