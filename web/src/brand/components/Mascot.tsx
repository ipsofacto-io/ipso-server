import * as React from 'react';
import { cx } from './cx';
import {
  IPSO_EYE,
  IPSO_EYES_X,
  IPSO_LEFT_BRACKET,
  IPSO_RATIO,
  IPSO_REJECT_INSET,
  IPSO_RIGHT_BRACKET,
  IPSO_RIGHT_OFFSET,
  IPSO_RING,
  IPSO_UNDERLINE_HEIGHT,
  IPSO_VERIFIED_FIELD,
  IPSO_VIEWBOX,
} from './brand-geometry';

export type MascotState = 'idle' | 'verifying' | 'verified' | 'needs-review' | 'rejected';
export type MascotTone = 'default' | 'mono' | 'action' | 'on-action';

export interface MascotProps extends Omit<React.SVGProps<SVGSVGElement>, 'height' | 'width' | 'ref'> {
  /** Follows the decision status. Always pair it with the Status component or the status word. */
  state?: MascotState;
  /** Height in px. Default 64, minimum 16. Width = size × 1.62. */
  size?: number;
  /** default: ink brackets + cursor eyes; mono: all ink; action / on-action: all in that token. */
  tone?: MascotTone;
  /** Alternative text. Default "Ipso" plus the state. Pass "" when Ipso is decorative. */
  label?: string;
}

const LABELS: Record<MascotState, string> = {
  idle: 'Ipso',
  verifying: 'Ipso, verifying',
  verified: 'Ipso, verified',
  'needs-review': 'Ipso, needs review',
  rejected: 'Ipso, rejected',
};

function Eyes({ className, y = IPSO_EYE.y, height = IPSO_EYE.height }: { className: string; y?: number; height?: number }) {
  return (
    <>
      {IPSO_EYES_X.map((x) => (
        <rect key={x} className={className} x={x} y={y} width={IPSO_EYE.width} height={height} />
      ))}
    </>
  );
}

/** Ipso, the mascot: two brackets and two letter-cell eyes. Follows the theme. */
export function Mascot({ state = 'idle', size = 64, tone = 'default', label, className, ...rest }: MascotProps) {
  const h = Math.max(size, 16);
  const w = Math.round(h * IPSO_RATIO * 100) / 100;
  const text = label === '' ? undefined : label ?? LABELS[state];
  const [eyeLeft, eyeRight] = IPSO_EYES_X;
  return (
    <svg
      {...rest}
      className={cx('ip-mascot', `ip-mascot-${state}`, tone !== 'default' && `ip-mascot-${tone}`, className)}
      width={w}
      height={h}
      viewBox={IPSO_VIEWBOX}
      role={text ? 'img' : undefined}
      aria-label={text}
      aria-hidden={text ? undefined : true}
    >
      {state === 'verified' && <rect className="ip-m-bg" {...IPSO_VERIFIED_FIELD} />}
      <path className="ip-m-b" d={IPSO_LEFT_BRACKET} />
      <path className="ip-m-b" transform={`translate(${IPSO_RIGHT_OFFSET} 0)`} d={IPSO_RIGHT_BRACKET} />
      {(state === 'idle' || state === 'verified') && <Eyes className="ip-m-e" />}
      {state === 'verifying' && (
        <>
          <Eyes className="ip-m-e ip-m-full" />
          <Eyes className="ip-m-e ip-m-under" y={IPSO_EYE.y + IPSO_EYE.height - IPSO_UNDERLINE_HEIGHT} height={IPSO_UNDERLINE_HEIGHT} />
        </>
      )}
      {state === 'needs-review' && (
        <>
          <rect
            className="ip-m-ring"
            x={eyeLeft + IPSO_RING / 2}
            y={IPSO_EYE.y + IPSO_RING / 2}
            width={IPSO_EYE.width - IPSO_RING}
            height={IPSO_EYE.height - IPSO_RING}
          />
          <rect className="ip-m-muted" x={eyeRight} y={IPSO_EYE.y} width={IPSO_EYE.width} height={IPSO_EYE.height} />
        </>
      )}
      {state === 'rejected' && (
        <path
          className="ip-m-x"
          d={IPSO_EYES_X.map((x) => {
            const [l, r] = [x + IPSO_REJECT_INSET.x, x + IPSO_EYE.width - IPSO_REJECT_INSET.x];
            const [t, b] = [IPSO_EYE.y + IPSO_REJECT_INSET.y, IPSO_EYE.y + IPSO_EYE.height - IPSO_REJECT_INSET.y];
            return `M${l} ${t}L${r} ${b}M${r} ${t}L${l} ${b}`;
          }).join('')}
        />
      )}
    </svg>
  );
}
