import { ChangeEvent, useEffect, useState } from 'react';

import { Input } from '../Input';

const SHORT_HEX_RE = /^#[0-9a-fA-F]{3}$/;
const FULL_HEX_RE = /^#[0-9a-fA-F]{6}$/;

export interface Props {
  value: string;
  onChange: (color: string) => void;
  'data-cy': string;
  id?: string;
  pickerId?: string;
}

export function ColorPicker({
  value,
  onChange,
  id = 'colorPickerTextInput',
  pickerId = 'colorPickerSwatch',
  'data-cy': dataCy = 'color-picker-input',
}: Props) {
  const [localHex, setLocalHex] = useState(value);
  const [isFocused, setIsFocused] = useState(false);

  useEffect(() => {
    if (!isFocused) {
      setLocalHex(value);
    }
  }, [value, isFocused]);

  const swatchColor = getSwatchColor(localHex, value);

  return (
    <div className="flex items-center gap-2">
      <label
        aria-label="Choose color"
        htmlFor={pickerId}
        className="form-control relative h-[34px] w-[34px] shrink-0 cursor-pointer overflow-hidden rounded !mb-0"
        style={{ backgroundColor: swatchColor }}
      >
        <input
          type="color"
          id={pickerId}
          value={swatchColor}
          onChange={handleColorChange}
          className="absolute inset-0 h-full w-full cursor-pointer opacity-0"
          aria-label="Choose highlight color"
        />
      </label>
      <Input
        id={id}
        value={localHex}
        onChange={handleTextChange}
        onFocus={() => setIsFocused(true)}
        onBlur={handleBlur}
        className="w-28 uppercase"
        maxLength={7}
        placeholder="e.g. #ffbbbb"
        spellCheck={false}
        data-cy={dataCy}
      />
    </div>
  );

  function handleColorChange(e: ChangeEvent<HTMLInputElement>) {
    const hex = e.target.value;
    setLocalHex(hex);
    onChange(hex);
  }

  function handleTextChange(e: ChangeEvent<HTMLInputElement>) {
    const raw = e.target.value;
    const normalized = raw.startsWith('#') ? raw : `#${raw}`;
    setLocalHex(normalized);
    if (isValidHex(normalized)) {
      onChange(expandHex(normalized));
    }
  }

  function handleBlur() {
    setIsFocused(false);
    if (!isValidHex(localHex)) {
      setLocalHex(value);
    }
  }
}

function isValidHex(hex: string): boolean {
  return SHORT_HEX_RE.test(hex) || FULL_HEX_RE.test(hex);
}

/** Expands a 3-digit shorthand (#rgb → #rrggbb). Full hex passes through unchanged. */
function expandHex(hex: string): string {
  if (SHORT_HEX_RE.test(hex)) {
    const [, r, g, b] = hex;
    return `#${r}${r}${g}${g}${b}${b}`;
  }
  return hex;
}

function getSwatchColor(localHex: string, committedValue: string): string {
  if (isValidHex(localHex)) {
    return expandHex(localHex);
  }
  if (isValidHex(committedValue)) {
    return expandHex(committedValue);
  }
  return '#ffffff';
}
