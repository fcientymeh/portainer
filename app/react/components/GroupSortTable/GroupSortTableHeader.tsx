import React from 'react';
import clsx from 'clsx';
import { ArrowDownAZ, ArrowDownZA, X } from 'lucide-react';

import { SearchBar } from '@@/datatables/SearchBar';
import { TooltipWithChildren } from '@@/Tip/TooltipWithChildren';

import { DropdownMenu, DropdownOption } from '../DropdownMenu/DropdownMenu';

export interface SortOption<TSortKey extends string> {
  key: TSortKey;
  label: string;
  dropdown?: {
    options: DropdownOption[];
    selected: string | null;
    onSelect: (value: string | null) => void;
  };
}

interface Props<TSortKey extends string> {
  sortBy: TSortKey;
  sortAsc?: boolean;
  onSortChange: (key: TSortKey) => void;
  onClear?: () => void;
  searchTerm: string;
  onSearchChange: (term: string) => void;
  sortOptions: SortOption<TSortKey>[];
  searchPlaceholder?: string;
  actionButton?: React.ReactNode;
  searchDataCy?: string;
}

const clearBtnClasses =
  'inline-flex items-center justify-center rounded-md border-0 bg-transparent p-1.5 transition-colors ' +
  'text-gray-8 hover:bg-gray-4 hover:text-gray-11 ' +
  'th-dark:text-gray-5 th-dark:hover:bg-gray-iron-9 th-dark:hover:text-white ' +
  'th-highcontrast:border th-highcontrast:border-solid th-highcontrast:border-white ' +
  'th-highcontrast:text-white th-highcontrast:hover:bg-white th-highcontrast:hover:text-black';

const baseBtn =
  'px-4 py-1.5 text-xs align-middle font-medium transition-colors';
const activeBtn =
  'z-10 border-none rounded-md font-medium ' +
  'bg-white text-gray-8 ' +
  'th-dark:bg-gray-iron-10 th-dark:text-white ' +
  'th-highcontrast:bg-white th-highcontrast:text-black';
const inactiveBtn =
  'text-muted border-none rounded-md ' +
  'bg-gray-4 hover:bg-gray-2 ' +
  'th-dark:bg-gray-iron-11 th-dark:text-white th-dark:hover:bg-gray-iron-9 ' +
  'th-highcontrast:bg-black th-highcontrast:text-white th-highcontrast:hover:bg-white th-highcontrast:hover:text-black';

export function GroupSortTableHeader<TSortKey extends string>({
  sortBy,
  sortAsc,
  onSortChange,
  onClear,
  searchTerm,
  onSearchChange,
  sortOptions,
  searchPlaceholder = 'Filter...',
  actionButton,
  searchDataCy,
}: Props<TSortKey>) {
  return (
    <div
      className={clsx(
        'flex items-center justify-between gap-3 px-5 py-3',
        'bg-gray-2 th-highcontrast:bg-black th-dark:bg-gray-iron-10'
      )}
    >
      <span
        className="text-xs font-semibold tracking-wider text-gray-11 th-highcontrast:text-white th-dark:text-white"
        data-cy="sort-by-label"
      >
        SORT BY:
      </span>
      <div
        className={clsx(
          'flex',
          'bg-gray-4 th-highcontrast:bg-black th-dark:bg-gray-iron-11',
          'gap-2 rounded-md p-1 th-highcontrast:border th-highcontrast:border-solid th-highcontrast:border-white'
        )}
        role="group"
      >
        {sortOptions.map((option, index) => {
          const isActive = sortBy === option.key;
          const isFirst = index === 0;
          const isLast = index === sortOptions.length - 1;
          const cornerClasses = clsx(
            isFirst && 'rounded-l-md',
            isLast && 'rounded-r-md'
          );
          const btnClasses = clsx(
            baseBtn,
            isActive ? activeBtn : inactiveBtn,
            cornerClasses
          );

          if (option.dropdown) {
            return (
              <DropdownMenu
                key={option.key}
                label={option.label}
                options={option.dropdown.options}
                selected={option.dropdown.selected}
                onSelect={option.dropdown.onSelect}
                badge={option.dropdown.selected}
                className={btnClasses}
                data-cy={`sort-by-${option.key.toLowerCase()}-button`}
              />
            );
          }

          return (
            <button
              key={option.key}
              type="button"
              onClick={() => onSortChange(option.key)}
              className={clsx(btnClasses, 'inline-flex items-center gap-1')}
              data-cy={`sort-by-${option.key.toLowerCase()}-button`}
            >
              {option.label}
              {isActive &&
                (sortAsc === false ? (
                  <ArrowDownZA className="h-3 w-3" aria-hidden="true" />
                ) : (
                  <ArrowDownAZ className="h-3 w-3" aria-hidden="true" />
                ))}
            </button>
          );
        })}
      </div>
      {onClear && (
        <TooltipWithChildren message="Clear all sort options" position="top">
          <button
            type="button"
            onClick={onClear}
            className={clearBtnClasses}
            aria-label="Clear all sort options"
            data-cy="clear-sort-options-button"
          >
            <X className="h-4 w-4" aria-hidden="true" />
          </button>
        </TooltipWithChildren>
      )}
      <div className="ml-auto flex items-center gap-2">
        <SearchBar
          value={searchTerm}
          placeholder={searchPlaceholder}
          onChange={onSearchChange}
          data-cy={searchDataCy || ''}
          className={clsx(
            'rounded-md border border-solid border-gray-4',
            'bg-white py-2 pl-9 pr-3 text-sm text-gray-10 placeholder-gray-6',
            'focus:border-blue-6 focus:outline-none',
            'th-dark:border-gray-7 th-dark:bg-gray-iron-10 th-dark:text-white th-dark:placeholder-gray-7',
            'th-highcontrast:border-white th-highcontrast:bg-black th-highcontrast:text-white th-highcontrast:placeholder-gray-4 th-highcontrast:focus:border-blue-8'
          )}
        />
        {actionButton}
      </div>
    </div>
  );
}
