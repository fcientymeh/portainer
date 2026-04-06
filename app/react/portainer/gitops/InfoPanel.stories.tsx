import { Meta, StoryObj } from '@storybook/react';

import { InfoPanel } from './InfoPanel';

const meta: Meta<typeof InfoPanel> = {
  component: InfoPanel,
  title: 'Forms/GitForm/InfoPanel',
  tags: ['autodocs'],
};

export default meta;
type Story = StoryObj<typeof InfoPanel>;

const baseDeployment = {
  repositoryUrl: 'https://github.com/portainer/portainer-ee',
  configFilePath: 'docker-compose.yml',
  additionalFiles: ['docker-compose.override.yml'],
  commitHash: 'a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2',
};

export const NoNextDeployment: Story = {
  name: 'No next deployment',
  args: {
    type: 'stack',
    currentDeployment: baseDeployment,
  },
};

export const NextDeploymentSame: Story = {
  name: 'Next deployment matches current',
  args: {
    type: 'stack',
    currentDeployment: baseDeployment,
    nextDeployment: { ...baseDeployment },
  },
};

export const NextDeploymentConfigChanged: Story = {
  name: 'Config file changed',
  args: {
    type: 'stack',
    currentDeployment: baseDeployment,
    nextDeployment: {
      ...baseDeployment,
      configFilePath: 'docker-compose.prod.yml',
      additionalFiles: [],
    },
  },
};

export const NextDeploymentUrlChanged: Story = {
  name: 'Repository URL changed',
  args: {
    type: 'stack',
    currentDeployment: baseDeployment,
    nextDeployment: {
      ...baseDeployment,
      repositoryUrl: 'https://github.com/portainer/portainer-ce',
    },
  },
};

export const NextDeploymentBothChanged: Story = {
  name: 'URL and config both changed',
  args: {
    type: 'stack',
    currentDeployment: baseDeployment,
    nextDeployment: {
      repositoryUrl: 'https://github.com/portainer/portainer-ce',
      configFilePath: 'docker-compose.prod.yml',
      additionalFiles: [],
      commitHash: baseDeployment.commitHash,
    },
  },
};

export const NoCommitHash: Story = {
  name: 'No commit hash',
  args: {
    type: 'stack',
    currentDeployment: { ...baseDeployment, commitHash: undefined },
  },
};
