import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { HttpResponse } from 'msw';

import { withTestRouter } from '@/react/test-utils/withRouter';
import { withUserProvider } from '@/react/test-utils/withUserProvider';
import { withTestQueryProvider } from '@/react/test-utils/withTestQuery';
import { createMockUsers } from '@/react-tools/test-mocks';
import { server, http } from '@/setup-tests/server';

import { StorageDatatable } from './StorageDatatable';

vi.mock('@/react/hooks/useEnvironmentId', () => ({
  useEnvironmentId: () => 1,
}));

vi.mock('@/portainer/services/notifications', () => ({
  notifyError: vi.fn(),
  notifySuccess: vi.fn(),
}));

const mockVolumes = [
  {
    persistentVolume: {
      capacity: {},
      persistentVolumeReclaimPolicy: 'Delete',
    },
    persistentVolumeClaim: {
      id: 'pvc-fast',
      name: 'pvc-fast',
      namespace: 'default',
      storage: 1073741824,
      creationDate: '2024-01-01T00:00:00Z',
      volumeName: 'pv-fast',
      storageClass: 'fast-ssd',
      phase: 'Bound',
    },
    storageClass: {
      name: 'fast-ssd',
      provisioner: 'kubernetes.io/no-provisioner',
      reclaimPolicy: 'Delete',
      allowVolumeExpansion: false,
    },
  },
  {
    persistentVolume: {
      capacity: {},
      persistentVolumeReclaimPolicy: 'Delete',
    },
    persistentVolumeClaim: {
      id: 'pvc-slow',
      name: 'pvc-slow',
      namespace: 'default',
      storage: 2147483648,
      creationDate: '2024-01-01T00:00:00Z',
      volumeName: 'pv-slow',
      storageClass: 'slow-hdd',
      phase: 'Bound',
    },
    storageClass: {
      name: 'slow-hdd',
      provisioner: 'kubernetes.io/no-provisioner',
      reclaimPolicy: 'Retain',
      allowVolumeExpansion: true,
    },
  },
];

beforeEach(() => {
  server.use(
    http.get('/api/kubernetes/1/volumes', () => HttpResponse.json(mockVolumes))
  );
});

const mockUser = createMockUsers(1, 1)[0];

function createTestComponent() {
  return withTestRouter(
    withUserProvider(withTestQueryProvider(StorageDatatable), mockUser),
    {
      route: '/kubernetes/volumes',
      stateConfig: [
        {
          name: 'kubernetes.volumes',
          url: '/kubernetes/volumes',
          params: { endpointId: '1' },
        },
        {
          name: 'kubernetes.volumes.volume',
          url: '/kubernetes/volumes/:name',
        },
      ],
    }
  );
}

describe('StorageDatatable', () => {
  it('renders storage class names', async () => {
    const TestComponent = createTestComponent();
    render(<TestComponent />);

    expect(await screen.findByText('fast-ssd')).toBeInTheDocument();
    expect(screen.getByText('slow-hdd')).toBeInTheDocument();
  });

  it('expanding one storage class does not expand others (regression R8S-538)', async () => {
    const TestComponent = createTestComponent();
    render(<TestComponent />);

    // Wait for rows to load
    await screen.findByText('fast-ssd');

    // Expand only the first storage class row
    const expandButton = screen.getByTestId('expand-row-button_0');
    const user = userEvent.setup();
    await user.click(expandButton);

    await waitFor(() => {
      // The volume under fast-ssd should now be visible
      expect(screen.getByText('pvc-fast')).toBeInTheDocument();

      // The volume under slow-hdd should NOT be visible
      expect(screen.queryByText('pvc-slow')).not.toBeInTheDocument();
    });
  });

  it('expand all button expands all storage classes', async () => {
    const TestComponent = createTestComponent();
    render(<TestComponent />);

    await screen.findByText('fast-ssd');

    const expandAllButton = screen.getByTestId('expand-all-rows-button');
    const user = userEvent.setup();
    await user.click(expandAllButton);

    await waitFor(() => {
      expect(screen.getByText('pvc-fast')).toBeInTheDocument();
      expect(screen.getByText('pvc-slow')).toBeInTheDocument();
    });
  });
});
