import { ReactNode } from 'react';
import clsx from 'clsx';
import { Briefcase } from 'lucide-react';

import './BEFeatureIndicator.css';

import { FeatureId } from '@/react/portainer/feature-flags/enums';

import { Icon } from '@@/Icon';

import { getFeatureDetails } from './utils';

export interface Props {
  featureId: FeatureId;
  showIcon?: boolean;
  className?: string;
  children?: (isLimited: boolean) => ReactNode;
}

export function BEFeatureIndicator({
  featureId,
  children = () => null,
  showIcon = true,
  className = '',
}: Props) {
  const { url, limitedToBE = false } = getFeatureDetails(featureId);

  return (
    <>

    </>
  );
}
