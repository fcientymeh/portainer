import { render, screen } from '@testing-library/react';

import { InfoPanel } from './InfoPanel';

const BASE_URL = 'https://github.com/portainer/portainer-compose';
const COMMIT_HASH = 'abc1234defgh';

const currentDeployment = {
  repositoryUrl: BASE_URL,
  configFilePath: 'docker-compose.yml',
  additionalFiles: ['extra.yml'],
  commitHash: COMMIT_HASH,
};

describe('InfoPanel', () => {
  describe('no nextDeployment (no-changes view)', () => {
    it('shows the deployed repository URL', () => {
      render(<InfoPanel type="stack" currentDeployment={currentDeployment} />);

      expect(screen.getByText(BASE_URL)).toBeVisible();
    });

    it('links to the commit hash', () => {
      render(<InfoPanel type="stack" currentDeployment={currentDeployment} />);

      const link = screen.getByRole('link', { name: COMMIT_HASH.slice(0, 7) });
      expect(link).toBeVisible();
      expect(link).toHaveAttribute('href', `${BASE_URL}/commit/${COMMIT_HASH}`);
    });

    it('shows "unknown" when commitHash is absent', () => {
      render(
        <InfoPanel
          type="stack"
          currentDeployment={{ ...currentDeployment, commitHash: undefined }}
        />
      );

      expect(screen.getByText(/unknown/i)).toBeVisible();
      expect(screen.queryByRole('link')).not.toBeInTheDocument();
    });

    it('lists the config and additional files', () => {
      render(<InfoPanel type="stack" currentDeployment={currentDeployment} />);

      expect(screen.getByText('docker-compose.yml, extra.yml')).toBeVisible();
    });

    it('works when additionalFiles is absent', () => {
      render(
        <InfoPanel
          type="stack"
          currentDeployment={{
            ...currentDeployment,
            additionalFiles: undefined,
          }}
        />
      );

      expect(screen.getByText('docker-compose.yml')).toBeVisible();
    });

    it('mentions the resource type in the description', () => {
      render(
        <InfoPanel type="application" currentDeployment={currentDeployment} />
      );

      expect(
        screen.getByText(
          /this application was deployed from the git repository/i
        )
      ).toBeVisible();
    });
  });

  describe('matching nextDeployment (no-changes view)', () => {
    it('does not show the diff view when nextDeployment equals currentDeployment', () => {
      render(
        <InfoPanel
          type="stack"
          currentDeployment={currentDeployment}
          nextDeployment={currentDeployment}
        />
      );

      expect(screen.queryByText(/currently deployed/i)).not.toBeInTheDocument();
      expect(screen.queryByText(/next deployment/i)).not.toBeInTheDocument();
    });

    it('treats absent additionalFiles as equal to an empty array', () => {
      render(
        <InfoPanel
          type="stack"
          currentDeployment={{ ...currentDeployment, additionalFiles: [] }}
          nextDeployment={{
            ...currentDeployment,
            additionalFiles: undefined,
          }}
        />
      );

      expect(screen.queryByText(/currently deployed/i)).not.toBeInTheDocument();
    });
  });

  describe('differing nextDeployment (diff view)', () => {
    const nextDeployment = {
      repositoryUrl: BASE_URL,
      configFilePath: 'docker-compose.prod.yml',
      additionalFiles: [],
    };

    it('shows "Currently deployed" and "Next deployment" headings', () => {
      render(
        <InfoPanel
          type="stack"
          currentDeployment={currentDeployment}
          nextDeployment={nextDeployment}
        />
      );

      expect(screen.getByText(/currently deployed/i)).toBeVisible();
      expect(screen.getByText(/next deployment/i)).toBeVisible();
    });

    it('shows current config file', () => {
      render(
        <InfoPanel
          type="stack"
          currentDeployment={currentDeployment}
          nextDeployment={nextDeployment}
        />
      );

      expect(screen.getByText('docker-compose.yml, extra.yml')).toBeVisible();
    });

    it('shows next config file', () => {
      render(
        <InfoPanel
          type="stack"
          currentDeployment={currentDeployment}
          nextDeployment={nextDeployment}
        />
      );

      expect(screen.getByText('docker-compose.prod.yml')).toBeVisible();
    });

    it('shows commit link for current deployment', () => {
      render(
        <InfoPanel
          type="stack"
          currentDeployment={currentDeployment}
          nextDeployment={nextDeployment}
        />
      );

      expect(
        screen.getByRole('link', { name: COMMIT_HASH.slice(0, 7) })
      ).toBeVisible();
    });

    it('does not show a repository line when URL is unchanged', () => {
      render(
        <InfoPanel
          type="stack"
          currentDeployment={currentDeployment}
          nextDeployment={nextDeployment}
        />
      );

      // The "Repository:" label only appears when the URL differs
      expect(screen.queryByText(/^repository:/i)).not.toBeInTheDocument();
    });

    it('shows the new repository URL when URL changes', () => {
      const newUrl = 'https://github.com/portainer/new-repo';

      render(
        <InfoPanel
          type="stack"
          currentDeployment={currentDeployment}
          nextDeployment={{ ...nextDeployment, repositoryUrl: newUrl }}
        />
      );

      expect(screen.getByText(/^repository:/i)).toBeVisible();
      expect(screen.getByText(newUrl)).toBeVisible();
    });

    it('shows "Pull from here to redeploy" instruction', () => {
      render(
        <InfoPanel
          type="stack"
          currentDeployment={currentDeployment}
          nextDeployment={nextDeployment}
        />
      );

      expect(screen.getByText(/pull from here to redeploy/i)).toBeVisible();
    });

    it('handles missing commitHash in current deployment', () => {
      render(
        <InfoPanel
          type="stack"
          currentDeployment={{ ...currentDeployment, commitHash: undefined }}
          nextDeployment={nextDeployment}
        />
      );

      expect(screen.queryByRole('link')).not.toBeInTheDocument();
    });
  });
});
