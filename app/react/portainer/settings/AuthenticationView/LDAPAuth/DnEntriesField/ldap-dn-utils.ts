export interface DnEntry {
  type: 'ou' | 'cn';
  value: string;
}

export function parseDN(
  dn: string | undefined,
  domainSuffix: string
): DnEntry[] {
  const regex = /(\w+)=([a-zA-Z0-9_ -]*),?/;
  const ouValues: DnEntry[] = [];
  let left = dn || '';
  let match = left.match(regex);

  while (match && left !== domainSuffix) {
    const [, type, value] = match;
    if (type === 'ou' || type === 'cn') {
      ouValues.push({ type: type as 'ou' | 'cn', value });
    }
    left = left.replace(regex, '');
    match = left.match(regex);
  }

  return ouValues;
}

export function buildDN(entries: DnEntry[], suffix: string): string {
  const dnParts = entries
    .filter(({ value }) => value)
    .map(({ type, value }) => `${type}=${value}`);

  if (suffix) {
    dnParts.push(suffix);
  }

  return dnParts.join(',');
}
