import { FilterBarButton, Color } from './FilterBarButton';
import { FilterBarActiveIndicator } from './FilterBarActiveIndicator';

export interface StatusSegment {
  key: string;
  label: string;
  count: number;
  color: Color;
}

interface Props {
  total: number;
  segments: StatusSegment[];
  value: string | null;
  onChange: (filter: string | null) => void;
  radioGroupName?: string;
  ariaLabel?: string;
  'data-cy'?: string;
}

export function StatusSummaryBar({
  total,
  segments,
  value,
  onChange,
  radioGroupName = 'status-summary-filter',
  ariaLabel = 'Filter by status',
  'data-cy': dataCy = 'status-summary-bar',
}: Props) {
  const isAllSelected = !value;
  const activeLabel = segments.find((s) => s.key === value)?.label;

  function handleSegmentClick(key: string) {
    onChange(value === key ? null : key);
  }

  return (
    <div
      className="relative flex items-stretch overflow-x-auto overflow-y-hidden rounded-lg border border-solid border-[var(--border-widget)] bg-[var(--bg-widget-color)]"
      data-cy={dataCy}
      role="radiogroup"
      aria-label={ariaLabel}
    >
      <FilterBarButton
        count={total}
        label="Total"
        isSelected={isAllSelected}
        onClick={() => onChange(null)}
        name={radioGroupName}
        data-cy={`${dataCy}-total`}
      />

      <Separator />

      {segments.map(({ key, label, count, color }) => (
        <FilterBarButton
          key={key}
          color={color}
          count={count}
          label={label}
          isSelected={value === key}
          onClick={() => handleSegmentClick(key)}
          name={radioGroupName}
          data-cy={`${dataCy}-${key}`}
        />
      ))}

      {activeLabel && (
        <div className="ml-auto hidden xl:flex">
          <Separator />
          <FilterBarActiveIndicator
            label={activeLabel}
            onClear={() => onChange(null)}
          />
        </div>
      )}
    </div>
  );
}

function Separator() {
  return (
    <div
      className="w-px shrink-0 self-stretch bg-[var(--border-widget)]"
      aria-hidden="true"
    />
  );
}
