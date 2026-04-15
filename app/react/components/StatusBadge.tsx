import clsx from 'clsx';
import { AriaAttributes, PropsWithChildren } from 'react';

import { Icon, IconProps } from '@@/Icon';

export type StatusBadgeType =
  | 'success'
  | 'danger'
  | 'warning'
  | 'info'
  | 'successLite'
  | 'dangerLite'
  | 'warningLite'
  | 'mutedLite'
  | 'infoLite'
  | 'default';

const typeClasses: Record<StatusBadgeType, string> = {
  success: clsx(
    'bg-success-7 text-white',
    'th-dark:bg-success-9 th-dark:text-white'
  ),
  warning: clsx(
    'bg-warning-7 text-white',
    'th-dark:bg-warning-9 th-dark:text-white'
  ),
  danger: clsx(
    'bg-error-7 text-white',
    'th-dark:bg-error-9 th-dark:text-white'
  ),
  info: clsx('bg-blue-7 text-white', 'th-dark:bg-blue-9 th-dark:text-white'),
  // the lite classes are a bit lighter in light mode and the same in dark mode
  successLite: clsx(
    'bg-success-3 text-success-9',
    'th-dark:bg-success-9 th-dark:text-white'
  ),
  warningLite: clsx(
    'bg-warning-3 text-warning-9',
    'th-dark:bg-warning-9 th-dark:text-white'
  ),
  dangerLite: clsx(
    'bg-error-3 text-error-9',
    'th-dark:bg-error-9 th-dark:text-white'
  ),
  mutedLite: clsx(
    'bg-gray-3 text-gray-9',
    'th-dark:bg-gray-9 th-dark:text-white'
  ),
  infoLite: clsx(
    'bg-blue-3 text-blue-9',
    'th-dark:bg-blue-9 th-dark:text-white'
  ),
  default: '',
};

export function StatusBadge({
  className,
  children,
  color = 'default',
  icon,
  ...aria
}: PropsWithChildren<
  {
    className?: string;
    color?: StatusBadgeType;
    icon?: IconProps['icon'];
  } & AriaAttributes
>) {
  return (
    <span
      className={clsx(
        'inline-flex items-center gap-1 rounded',
        'w-fit px-1.5 py-0.5',
        'text-sm font-medium',
        typeClasses[color],
        className
      )}
      // eslint-disable-next-line react/jsx-props-no-spreading
      {...aria}
    >
      {icon && (
        <Icon
          icon={icon}
          className={clsx({
            '!text-green-7': color === 'success',
            '!text-warning-7': color === 'warning',
            '!text-error-7': color === 'danger',
          })}
        />
      )}

      {children}
    </span>
  );
}
