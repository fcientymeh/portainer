import clsx from 'clsx';
import { PropsWithChildren } from 'react';

import { AutomationTestingProps } from '@/types';

export type BadgeType =
  | 'success'
  | 'danger'
  | 'warn'
  | 'info'
  | 'successSecondary'
  | 'dangerSecondary'
  | 'warnSecondary'
  | 'infoSecondary'
  | 'muted';

// the classes are typed in full because tailwind doesn't render the interpolated classes
const typeClasses: Record<BadgeType, string> = {
  success: clsx(
    'bg-success-2 text-success-9',
    'th-dark:bg-success-10 th-dark:text-success-3',
    'th-highcontrast:bg-success-10 th-highcontrast:text-success-3'
  ),
  warn: clsx(
    'bg-warning-2 text-warning-9',
    'th-dark:bg-warning-10 th-dark:text-warning-3',
    'th-highcontrast:bg-warning-10 th-highcontrast:text-warning-3'
  ),
  danger: clsx(
    'bg-error-2 text-error-9',
    'th-dark:bg-error-10 th-dark:text-error-3',
    'th-highcontrast:bg-error-10 th-highcontrast:text-error-3'
  ),
  info: clsx(
    'bg-blue-2 text-blue-9',
    'th-dark:bg-blue-10 th-dark:text-blue-3',
    'th-highcontrast:bg-blue-10 th-highcontrast:text-blue-3'
  ),
  // the secondary classes are a bit darker in light mode and a bit lighter in dark mode
  successSecondary: clsx(
    'bg-success-3 text-success-9',
    'th-dark:bg-success-9 th-dark:text-success-3',
    'th-highcontrast:bg-success-9 th-highcontrast:text-success-3'
  ),
  warnSecondary: clsx(
    'bg-warning-3 text-warning-9',
    'th-dark:bg-warning-9 th-dark:text-warning-3',
    'th-highcontrast:bg-warning-9 th-highcontrast:text-warning-3'
  ),
  dangerSecondary: clsx(
    'bg-error-3 text-error-9',
    'th-dark:bg-error-9 th-dark:text-error-3',
    'th-highcontrast:bg-error-9 th-highcontrast:text-error-3'
  ),
  infoSecondary: clsx(
    'bg-blue-3 text-blue-9',
    'th-dark:bg-blue-9 th-dark:text-blue-3',
    'th-highcontrast:bg-blue-9 th-highcontrast:text-blue-3'
  ),
  muted: clsx(
    'bg-gray-3 text-gray-9',
    'th-dark:bg-gray-9 th-dark:text-gray-3',
    'th-highcontrast:bg-gray-9 th-highcontrast:text-gray-3'
  ),
};

export interface Props {
  type?: BadgeType;
  className?: string;
}

// this component is used in tables and lists in portainer. It looks like this:
// https://www.figma.com/file/g5TUMngrblkXM7NHSyQsD1/New-UI?node-id=76%3A2
export function Badge({
  type = 'info',
  className,
  children,
  'data-cy': dataCy,
}: PropsWithChildren<Props> & Partial<AutomationTestingProps>) {
  const baseClasses =
    'inline-flex w-fit items-center !text-xs font-medium rounded-full px-2 py-0.5';

  return (
    <span
      className={clsx(baseClasses, typeClasses[type], className)}
      role="status"
      data-cy={dataCy}
    >
      {children}
    </span>
  );
}
