import { PropsWithChildren } from 'react';

export function PageTitle({
  title,
  children,
}: PropsWithChildren<{ title: string }>) {
  return (
    <div className="flex items-center gap-2 px-[15px] pt-3">
      <h1
        className="m-0 text-2xl font-medium text-gray-11 th-highcontrast:text-white th-dark:text-white"
        data-cy="page-title"
      >
        {title}
      </h1>
      {children}
    </div>
  );
}
