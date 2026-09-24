import type { ComponentProps } from 'react';

import { cn } from '@/lib/utils';
import { Loader2Icon } from 'lucide-react';

type SpinnerSvg = Omit<ComponentProps<'svg'>, 'aria-hidden' | 'aria-label' | 'role'>;

type SpinnerProps = SpinnerSvg & ({ decorative: true } | { label: string });

function Spinner(props: SpinnerProps) {
  if ('decorative' in props) {
    const { className, decorative: _decorative, ...svgProps } = props;
    return (
      <Loader2Icon
        data-slot="spinner"
        aria-hidden="true"
        className={cn('size-4 animate-spin', className)}
        {...svgProps}
      />
    );
  }

  const { className, label, ...svgProps } = props;
  return (
    <Loader2Icon
      data-slot="spinner"
      role="status"
      aria-label={label}
      className={cn('size-4 animate-spin', className)}
      {...svgProps}
    />
  );
}

export { Spinner };
