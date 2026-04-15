import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, it, expect, vi } from 'vitest';

import { DnBuilder } from './DnBuilder';

describe('DnBuilder', () => {
  it('does not call onChange on initial render when value already matches suffix', () => {
    const onChange = vi.fn();
    const suffix = 'dc=example,dc=com';

    render(<DnBuilder value={suffix} suffix={suffix} onChange={onChange} />);

    expect(onChange).not.toHaveBeenCalled();
  });

  it('calls onChange with the correct DN when an entry changes', async () => {
    const user = userEvent.setup();
    const onChange = vi.fn();

    render(
      <DnBuilder
        value="ou=Users,dc=example,dc=com"
        suffix="dc=example,dc=com"
        onChange={onChange}
      />
    );

    const input = screen.getByRole('textbox');
    await user.type(input, 'X');

    expect(onChange).toHaveBeenLastCalledWith('ou=UsersX,dc=example,dc=com');
  });

  it('re-parses entries when value prop changes without calling onChange', () => {
    const onChange = vi.fn();
    const suffix = 'dc=example,dc=com';

    const { rerender } = render(
      <DnBuilder
        value="ou=users,dc=example,dc=com"
        suffix={suffix}
        onChange={onChange}
      />
    );

    onChange.mockClear();

    rerender(
      <DnBuilder
        value="ou=admins,dc=example,dc=com"
        suffix={suffix}
        onChange={onChange}
      />
    );

    expect(onChange).not.toHaveBeenCalled();
    expect(screen.getByRole('textbox')).toHaveValue('admins');
  });
});
