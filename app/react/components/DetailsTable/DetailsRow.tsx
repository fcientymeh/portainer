import clsx from 'clsx';
import { ReactNode } from 'react';

interface Props {
  children: ReactNode;
  label: ReactNode;
  colClassName?: string;
  className?: string;
  columns?: Array<ReactNode>;
  ariaLabel?: string;
}

export function DetailsRow({
  label,
  children,
  colClassName,
  className,
  columns,
  ariaLabel,
}: Props) {
  const labelString = typeof label === 'string' ? label : undefined;
  return (
    <tr className={className} aria-label={ariaLabel ?? labelString}>
      <td className={clsx(colClassName, '!break-normal')}>{label}</td>
      <td className={colClassName} data-cy={`detailsTable-${label}Value`}>
        {children}
      </td>
      {columns?.map((column, index) => (
        <td key={index} className={colClassName}>
          {column}
        </td>
      ))}
    </tr>
  );
}
