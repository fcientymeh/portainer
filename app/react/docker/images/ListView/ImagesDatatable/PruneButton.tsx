import { BrushCleaning, Check } from 'lucide-react';

import { useEnvironmentId } from '@/react/hooks/useEnvironmentId';
import { notifySuccess, notifyError } from '@/portainer/services/notifications';
import { Authorized } from '@/react/hooks/useUser';
import { humanize } from '@/portainer/filters/filters';

import { LoadingButton } from '@@/buttons';
import { TooltipWithChildren } from '@@/Tip/TooltipWithChildren';

import { usePruneImagesMutation } from '../../queries/usePruneImagesMutation';
import { ImagesListResponse } from '../../queries/useImages';

import { confirmPruneImages } from './ConfirmPruneModal';

interface Props {
  images: ImagesListResponse[];
}

export function PruneButton({ images }: Props) {
  const environmentId = useEnvironmentId();
  const pruneImagesMutation = usePruneImagesMutation(environmentId);

  const hasPrunableImages = images.some((image) => !image.used);

  const button = (
    <LoadingButton
      color="default"
      icon={hasPrunableImages ? BrushCleaning : Check}
      onClick={handlePrune}
      isLoading={pruneImagesMutation.isLoading}
      loadingText="Pruning..."
      data-cy="image-pruneButton"
      disabled={!hasPrunableImages}
    >
      Prune
    </LoadingButton>
  );

  if (hasPrunableImages) {
    return (
      <Authorized authorizations="DockerImagePrune" adminOnlyCE>
        {button}
      </Authorized>
    );
  }

  return (
    <Authorized authorizations="DockerImagePrune" adminOnlyCE>
      <TooltipWithChildren message="No unused images available to prune">
        <span>{button}</span>
      </TooltipWithChildren>
    </Authorized>
  );

  async function handlePrune() {
    const result = await confirmPruneImages(images);

    if (!result) {
      return;
    }

    pruneImagesMutation.mutate(
      { all: result.pruneAll },
      {
        onSuccess: (data) => {
          const space = humanize(data.SpaceReclaimed);
          notifySuccess('Images pruned', `Reclaimed ${space}`);
        },
        onError: (error) => {
          notifyError('Failed to prune images', error);
        },
      }
    );
  }
}
