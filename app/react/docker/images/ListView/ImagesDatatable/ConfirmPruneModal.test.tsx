import { screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';

import { confirmPruneImages } from './ConfirmPruneModal';

describe('ConfirmPruneModal', () => {
  afterEach(() => {
    // Clean up any modal elements
    document.body
      .querySelectorAll('[data-reach-dialog-overlay]')
      .forEach((el) => el.remove());
    document.body
      .querySelectorAll('[id^="dialog-"]')
      .forEach((el) => el.remove());
  });

  it('should render modal with title and description', async () => {
    confirmPruneImages();

    await waitFor(() => {
      expect(screen.getByText('Are you sure?')).toBeVisible();
      expect(
        screen.getByText(/This will delete all untagged \(dangling\) images/)
      ).toBeVisible();
    });
  });

  it('should render switch for pruning all unused images', async () => {
    confirmPruneImages();

    await waitFor(() => {
      expect(screen.getByText('Delete all unused images')).toBeVisible();
    });
  });

  it('should return undefined when Cancel is clicked', async () => {
    const user = userEvent.setup();
    const resultPromise = confirmPruneImages();

    const cancelButton = await screen.findByRole('button', { name: /cancel/i });
    await user.click(cancelButton);

    const result = await resultPromise;
    expect(result).toBeUndefined();
  });

  it('should return pruneAll: false when Continue is clicked without toggling switch', async () => {
    const user = userEvent.setup();
    const resultPromise = confirmPruneImages();

    const confirmButton = await screen.findByRole('button', {
      name: /continue/i,
    });
    await user.click(confirmButton);

    const result = await resultPromise;
    expect(result).toEqual({ pruneAll: false });
  });

  it('should return pruneAll: true when switch is toggled and Continue is clicked', async () => {
    const user = userEvent.setup();
    const resultPromise = confirmPruneImages();

    const switchInput = await screen.findByRole('checkbox');
    await user.click(switchInput);

    const confirmButton = screen.getByRole('button', { name: /continue/i });
    await user.click(confirmButton);

    const result = await resultPromise;
    expect(result).toEqual({ pruneAll: true });
  });

  it('should have switch unchecked by default', async () => {
    confirmPruneImages();

    const switchInput = await screen.findByRole('checkbox');
    expect(switchInput).not.toBeChecked();
  });

  it('should show validation message when no untagged images but unused images exist', async () => {
    confirmPruneImages([
      {
        id: 'img1',
        used: false,
        tags: ['tag1'],
        created: 1234567890,
        size: 1024,
      }, // unused but tagged
    ]);

    await waitFor(() => {
      expect(
        screen.getByText(
          /No untagged \(dangling\) images available to delete\./
        )
      ).not.toHaveClass('invisible');
    });
  });

  it('should not show validation message when untagged images exist', async () => {
    confirmPruneImages([
      {
        id: 'img1',
        used: true,
        tags: [],
        created: 1234567890,
        size: 1024,
      }, // untagged
    ]);

    await waitFor(() => {
      expect(
        screen.getByText(
          /No untagged \(dangling\) images available to delete\./
        )
      ).toHaveClass('invisible');
    });
  });

  it('should not show validation message when switch is toggled', async () => {
    const user = userEvent.setup();
    confirmPruneImages([
      {
        id: 'img1',
        used: false,
        tags: ['tag1'],
        created: 1234567890,
        size: 1024,
      }, // unused but tagged
    ]);

    await waitFor(() => {
      expect(
        screen.getByText(
          /No untagged \(dangling\) images available to delete\./
        )
      ).not.toHaveClass('invisible');
    });

    const switchInput = await screen.findByRole('checkbox');
    await user.click(switchInput);

    await waitFor(() => {
      expect(
        screen.getByText(
          /No untagged \(dangling\) images available to delete\./
        )
      ).toHaveClass('invisible');
    });
  });
});
