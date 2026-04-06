import { useCallback, useEffect, useState } from 'react';

import { FeatureId } from '@/react/portainer/feature-flags/enums';

import { DnEntriesField } from './DnEntriesField';
import { parseDN, buildDN, DnEntry } from './ldap-dn-utils';

interface Props {
  value: string | undefined;
  suffix: string;
  onChange: (dn: string) => void;
  label?: string;
  limitedFeatureId?: FeatureId;
}

export function DnBuilder({
  value,
  suffix,
  onChange,
  label,
  limitedFeatureId,
}: Props) {
  const [entries, setEntries] = useState<DnEntry[]>([]);

  const handleEntriesChange = useCallback(
    (newEntries: DnEntry[]) => {
      setEntries(newEntries);
      const dn = buildDN(newEntries, suffix);
      if (dn !== value) {
        onChange(dn);
      }
    },
    [suffix, value, onChange]
  );

  useEffect(() => {
    handleEntriesChange(parseDN(value, suffix));
  }, [value, suffix, handleEntriesChange]);

  return (
    <DnEntriesField
      value={entries}
      onChange={handleEntriesChange}
      label={label}
      limitedFeatureId={limitedFeatureId}
    />
  );
}
