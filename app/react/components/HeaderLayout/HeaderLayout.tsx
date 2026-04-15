import { ReactNode } from 'react';
import clsx from 'clsx';

import { InlineLoader } from '@@/InlineLoader';
import { Alert } from '@@/Alert';
import { Widget } from '@@/Widget';

interface Props {
  // Data states
  isLoading: boolean;
  errorMessage?: string;

  // Icon section
  icon: ReactNode;
  iconBackgroundClassName?: string;

  // Header section
  subtitleLabel?: string;
  subtitleClassName?: string;
  title: string;
  badge?: ReactNode;
  description?: ReactNode;

  // Right side info
  rightInfo?: ReactNode;

  // Customization
  containerClassName?: string;
  widgetClassName?: string;
}

export function HeaderLayout({
  isLoading,
  errorMessage,
  icon,
  iconBackgroundClassName = 'bg-group-accent-3 th-dark:bg-group-accent-10',
  subtitleLabel,
  subtitleClassName = 'text-group-accent-10 th-dark:text-group-accent-8',
  title,
  badge,
  description,
  rightInfo,
  containerClassName = 'flex items-center gap-4 p-4',
  widgetClassName = '!border border-solid border-gray-4 th-dark:border-widget th-highcontrast:border-gray-11',
}: Props) {
  if (isLoading) {
    return (
      <Widget className={widgetClassName}>
        <div className={containerClassName}>
          <InlineLoader>Loading details...</InlineLoader>
        </div>
      </Widget>
    );
  }

  if (errorMessage) {
    return (
      <Widget className={widgetClassName}>
        <div className={containerClassName}>
          <Alert color="error" title="Error">
            {errorMessage}
          </Alert>
        </div>
      </Widget>
    );
  }

  return (
    <Widget className={widgetClassName}>
      <div className={containerClassName}>
        {/* Icon container */}
        <div
          className={clsx(
            'flex h-14 w-14 shrink-0 items-center justify-center rounded-lg text-3xl',
            iconBackgroundClassName
          )}
        >
          {icon}
        </div>

        {/* Header info */}
        <div className="flex flex-1 flex-col gap-0">
          {subtitleLabel && (
            <div className="flex items-center gap-2">
              <span className={clsx('text-xs font-medium', subtitleClassName)}>
                {subtitleLabel}
              </span>
            </div>
          )}
          <div className="flex items-center gap-2">
            <span className="text-lg font-bold">{title}</span>
            {badge && <div className="flex flex-wrap gap-1">{badge}</div>}
          </div>
          {description && (
            <span className="text-xs text-muted">{description}</span>
          )}
        </div>

        {/* Right-side info */}
        {rightInfo && (
          <div className="flex items-center gap-6">{rightInfo}</div>
        )}
      </div>
    </Widget>
  );
}
