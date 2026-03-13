import { PropsWithChildren, ReactNode, useState } from 'react';

import { CollapseExpandButton } from '@@/CollapseExpandButton';

import { FormSectionTitle } from '../FormSectionTitle';

interface Props {
  title: ReactNode;
  titleSize?: 'sm' | 'md' | 'lg';
  isFoldable?: boolean;
  defaultFolded?: boolean;
  titleClassName?: string;
  className?: string;
  htmlFor?: string;
  setIsDefaultFolded?: (isDefaultFolded: boolean) => void;
  id?: string;
}

export function FormSection({
  title,
  titleSize = 'md',
  children,
  isFoldable = false,
  defaultFolded = isFoldable,
  titleClassName,
  className,
  htmlFor = '',
  setIsDefaultFolded,
  id,
}: PropsWithChildren<Props>) {
  const [isExpanded, setIsExpanded] = useState(!defaultFolded);
  const collapsibleIdSuffix = typeof title === 'string' ? title : id;
  const collapsibleId = collapsibleIdSuffix
    ? `foldingButton${collapsibleIdSuffix}`
    : undefined;

  return (
    <div className={className} id={id}>
      <FormSectionTitle
        htmlFor={isFoldable ? collapsibleId : htmlFor}
        titleSize={titleSize}
        className={titleClassName}
      >
        {isFoldable && (
          <CollapseExpandButton
            isExpanded={isExpanded}
            data-cy={collapsibleId}
            id={collapsibleId}
            onClick={() => {
              setIsExpanded((isExpanded) => !isExpanded);
              setIsDefaultFolded?.(isExpanded);
            }}
          />
        )}

        {title}
      </FormSectionTitle>
      {/* col-sm-12 in the title has a 'float: left' style - 'clear-both' makes sure it doesn't get in the way of the next div */}
      {/* https://stackoverflow.com/questions/7759837/put-divs-below-floatleft-divs */}
      <div className="clear-both">{isExpanded && children}</div>
    </div>
  );
}
