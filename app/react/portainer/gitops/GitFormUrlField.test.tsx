import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { vi } from 'vitest';
import { HttpResponse } from 'msw';

import { withTestQueryProvider } from '@/react/test-utils/withTestQuery';
import { useDebounce } from '@/react/hooks/useDebounce';
import { server, http } from '@/setup-tests/server';
import { suppressConsoleLogs } from '@/setup-tests/suppress-console';

import { GitFormModel } from './types';
import { GitFormUrlField } from './GitFormUrlField';
import { getAuthentication } from './utils';

vi.mock('@/react/hooks/useDebounce', () => ({
  useDebounce: vi.fn(),
}));

vi.mock('../feature-flags/feature-flags.service', () => ({
  isBE: true,
}));

vi.mock('./utils', async (importActual) => ({
  ...(await importActual()),
  getAuthentication: vi.fn(),
}));

const mockUseDebounce = vi.mocked(useDebounce);
const mockGetAuthentication = vi.mocked(getAuthentication);

describe('GitFormUrlField', () => {
  const defaultModel: GitFormModel = {
    RepositoryURL: '',
    ComposeFilePathInRepository: '',
    RepositoryAuthentication: false,
    RepositoryURLValid: false,
    TLSSkipVerify: false,
  };

  const defaultProps = {
    value: '',
    onChange: vi.fn(),
    onChangeRepositoryValid: vi.fn(),
    model: defaultModel,
  };

  beforeEach(() => {
    vi.clearAllMocks();
    mockUseDebounce.mockImplementation((value, onChange) => [value, onChange]);
    mockGetAuthentication.mockReturnValue(undefined);
  });

  function renderComponent(props = {}) {
    const Component = withTestQueryProvider(() => (
      <GitFormUrlField {...defaultProps} {...props} />
    ));
    return render(<Component />);
  }

  describe('Basic rendering', () => {
    it('should render with correct structure', () => {
      renderComponent();

      expect(screen.getByText(/repository url/i)).toBeInTheDocument();
      expect(
        screen.getByPlaceholderText(
          'e.g. https://github.com/portainer/portainer-compose'
        )
      ).toBeInTheDocument();
      expect(screen.getByTestId('component-gitUrlInput')).toBeInTheDocument();
      expect(
        screen.getByTestId('component-gitUrlRefreshButton')
      ).toBeInTheDocument();
    });

    it('should display the current value in the input', () => {
      const testUrl = 'https://github.com/test/repo';
      renderComponent({ value: testUrl });

      expect(screen.getByDisplayValue(testUrl)).toBeInTheDocument();
    });

    it('should mark input as required', () => {
      renderComponent();

      const input = screen.getByTestId('component-gitUrlInput');
      expect(input).toHaveAttribute('required');
    });

    it('should have correct input name and type', () => {
      renderComponent();

      const input = screen.getByTestId('component-gitUrlInput');
      expect(input).toHaveAttribute('name', 'repoUrlField');
      expect(input).toHaveAttribute('type', 'text');
    });
  });

  describe('Input handling', () => {
    it('should call onChange when input value changes', async () => {
      const user = userEvent.setup();
      const mockOnChange = vi.fn();
      renderComponent({ onChange: mockOnChange });

      const input = screen.getByTestId('component-gitUrlInput');
      await user.clear(input);
      await user.type(input, 'test');

      expect(mockOnChange).toHaveBeenCalledWith('t');
      expect(mockOnChange).toHaveBeenCalledWith('e');
      expect(mockOnChange).toHaveBeenCalledWith('s');
      expect(mockOnChange).toHaveBeenLastCalledWith('t');
    });

    it('should use debounced value and onChange', () => {
      const debouncedValue = 'debounced-value';
      const debouncedOnChange = vi.fn();
      mockUseDebounce.mockReturnValue([debouncedValue, debouncedOnChange]);

      renderComponent();

      expect(screen.getByDisplayValue(debouncedValue)).toBeInTheDocument();
    });
  });

  describe('Repository validation', () => {
    it('should display error message when repo check fails with Portainer error', async () => {
      const restoreConsole = suppressConsoleLogs();

      const errorMessage = 'Repository not found';
      server.use(
        http.post('/api/gitops/repo/refs', () =>
          HttpResponse.json(
            { message: errorMessage, details: errorMessage },
            { status: 422 }
          )
        )
      );

      renderComponent({ value: 'https://github.com/test/repo' });

      await waitFor(() =>
        expect(screen.getByText(errorMessage)).toBeInTheDocument()
      );

      restoreConsole();
    });

    it('should not display error message when repo check fails with non-Portainer error', async () => {
      const restoreConsole = suppressConsoleLogs();

      server.use(
        http.post('/api/gitops/repo/refs', () =>
          HttpResponse.json('Network error', { status: 500 })
        )
      );

      renderComponent({ value: 'https://github.com/test/repo' });

      await waitFor(() =>
        expect(
          screen.queryByLabelText('Checking repository')
        ).not.toBeInTheDocument()
      );

      expect(screen.queryByText('Network error')).not.toBeInTheDocument();

      restoreConsole();
    });

    it('should transform "Authentication required" error when no creds', async () => {
      const restoreConsole = suppressConsoleLogs();

      server.use(
        http.post('/api/gitops/repo/refs', () =>
          HttpResponse.json(
            {
              message: 'Authentication required: Repository not found.',
              details: 'Authentication required: Repository not found.',
            },
            { status: 422 }
          )
        )
      );

      renderComponent({ value: 'https://github.com/private/repo' });

      await waitFor(() =>
        expect(
          screen.getByText(
            'Git repository could not be found or is private, please ensure that the URL is correct or credentials are provided.'
          )
        ).toBeInTheDocument()
      );

      restoreConsole();
    });

    it('should display custom errors prop', () => {
      const customError = 'Custom validation error';
      renderComponent({ errors: customError });

      expect(screen.getByText(customError)).toBeInTheDocument();
    });

    it('should prioritize repo error message over custom errors', async () => {
      const restoreConsole = suppressConsoleLogs();

      const repoError = 'Repository error';
      const customError = 'Custom validation error';

      server.use(
        http.post('/api/gitops/repo/refs', () =>
          HttpResponse.json(
            { message: repoError, details: repoError },
            { status: 422 }
          )
        )
      );

      renderComponent({
        value: 'https://github.com/test/repo',
        errors: customError,
      });

      await waitFor(() =>
        expect(screen.getByText(repoError)).toBeInTheDocument()
      );
      expect(screen.queryByText(customError)).not.toBeInTheDocument();

      restoreConsole();
    });
  });

  describe('Status icons', () => {
    it('should show no status when URL is empty', () => {
      renderComponent({ value: '' });

      expect(
        screen.queryByLabelText('Checking repository')
      ).not.toBeInTheDocument();
      expect(
        screen.queryByLabelText('Repository detected')
      ).not.toBeInTheDocument();
      expect(
        screen.queryByLabelText(
          'Repository does not exist, or is not accessible'
        )
      ).not.toBeInTheDocument();
    });

    it('should announce repository detected when repo is valid', async () => {
      renderComponent({ value: 'https://github.com/test/repo' });

      await waitFor(() =>
        expect(screen.getByLabelText('Repository detected')).toBeInTheDocument()
      );
    });

    it('should announce inaccessible when repo check fails and is fetched', async () => {
      const restoreConsole = suppressConsoleLogs();

      server.use(
        http.post('/api/gitops/repo/refs', () =>
          HttpResponse.json(
            { message: 'not found', details: '' },
            { status: 422 }
          )
        )
      );

      renderComponent({ value: 'https://github.com/test/repo' });

      await waitFor(() =>
        expect(
          screen.getByLabelText(
            'Repository does not exist, or is not accessible'
          )
        ).toBeInTheDocument()
      );

      restoreConsole();
    });

    it('should not announce inaccessible while still loading', async () => {
      let resolveRequest!: () => void;
      const requestPending = new Promise<void>((resolve) => {
        resolveRequest = resolve;
      });

      server.use(
        http.post('/api/gitops/repo/refs', async () => {
          await requestPending;
          return HttpResponse.json(['refs/heads/main']);
        })
      );

      renderComponent({ value: 'https://github.com/test/repo' });

      await waitFor(() =>
        expect(screen.getByLabelText('Checking repository')).toBeInTheDocument()
      );

      expect(
        screen.queryByLabelText(
          'Repository does not exist, or is not accessible'
        )
      ).not.toBeInTheDocument();

      resolveRequest();
    });
  });

  describe('Refresh functionality', () => {
    it('should disable refresh button when repository is not valid', () => {
      renderComponent({
        model: { ...defaultModel, RepositoryURLValid: false },
      });

      expect(
        screen.getByTestId('component-gitUrlRefreshButton')
      ).toBeDisabled();
    });

    it('should enable refresh button when repository is valid', () => {
      renderComponent({ model: { ...defaultModel, RepositoryURLValid: true } });

      expect(
        screen.getByTestId('component-gitUrlRefreshButton')
      ).not.toBeDisabled();
    });

    it('should send force=true as query param when refresh is clicked', async () => {
      const user = userEvent.setup();

      const requestUrls: string[] = [];
      server.use(
        http.post('/api/gitops/repo/refs', ({ request }) => {
          requestUrls.push(request.url);
          return HttpResponse.json(['refs/heads/main']);
        })
      );

      renderComponent({
        value: 'https://github.com/test/repo',
        model: { ...defaultModel, RepositoryURLValid: true },
      });

      await waitFor(() => expect(requestUrls).toHaveLength(1));

      await user.click(screen.getByRole('button', { name: /Refresh/ }));

      await waitFor(() => expect(requestUrls).toHaveLength(2));

      expect(new URL(requestUrls[1]).searchParams.get('force')).toBe('true');
    });
  });
});
