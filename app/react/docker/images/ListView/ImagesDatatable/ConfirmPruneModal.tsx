import { useState } from 'react';
import clsx from 'clsx';

import { Modal, OnSubmit, ModalType, openModal } from '@@/modals';
import { Button } from '@@/buttons';
import { SwitchField } from '@@/form-components/SwitchField';

import { ImagesListResponse } from '../../queries/useImages';

interface Props {
  onSubmit: OnSubmit<{ pruneAll: boolean }>;
  images?: ImagesListResponse[];
}

function ConfirmPruneModal({ onSubmit, images = [] }: Props) {
  const [pruneAll, setPruneAll] = useState(false);

  const hasUntaggedImages = images.some(
    (img) => !img.tags || img.tags.length === 0
  );
  const hasUnusedImages = images.some((img) => !img.used);
  const showValidationMessage =
    !pruneAll && !hasUntaggedImages && hasUnusedImages;

  return (
    <Modal onDismiss={() => onSubmit()} aria-label="confirm prune images modal">
      <Modal.Header title="Are you sure?" modalType={ModalType.Destructive} />
      <Modal.Body>
        <p>
          This will delete all untagged (dangling) images in this environment.
        </p>
        <SwitchField
          name="pruneAll"
          data-cy="prune-all-unused-switch"
          label="Delete all unused images"
          tooltip="Delete all unused images, even if they are tagged."
          checked={pruneAll}
          onChange={setPruneAll}
        />
        <p
          className={clsx(
            'text-muted mt-1 text-xs',
            // use invisible class to avoid layout shift
            showValidationMessage ? 'visible' : 'invisible'
          )}
        >
          No untagged (dangling) images available to delete.
        </p>
      </Modal.Body>
      <Modal.Footer>
        <Button
          onClick={() => onSubmit()}
          color="default"
          data-cy="prune-cancel"
        >
          Cancel
        </Button>
        <Button
          onClick={() => onSubmit({ pruneAll })}
          color="danger"
          data-cy="prune-confirm"
        >
          Continue
        </Button>
      </Modal.Footer>
    </Modal>
  );
}

export async function confirmPruneImages(images?: ImagesListResponse[]) {
  return openModal(ConfirmPruneModal, { images });
}
