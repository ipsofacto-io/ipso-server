import * as React from 'react';
import { cx } from './cx';

export type ButtonVariant = 'primary' | 'secondary' | 'quiet' | 'danger';

type Common = {
  /** One primary per view: the action that moves the decision forward. Default secondary. */
  variant?: ButtonVariant;
  /** md 44px (default) · sm 36px. */
  size?: 'md' | 'sm';
  className?: string;
  children?: React.ReactNode;
};

export type ButtonProps =
  | (Common & { href?: undefined } & React.ButtonHTMLAttributes<HTMLButtonElement>)
  | (Common & { href: string } & React.AnchorHTMLAttributes<HTMLAnchorElement>);

/** Action button. With `href` it renders as a link styled as a button. */
export function Button(props: ButtonProps) {
  const { variant = 'secondary', size = 'md', className, children, ...rest } = props;
  const cls = cx('ip-btn', `ip-btn-${variant}`, size === 'sm' && 'ip-btn-sm', className);
  if (typeof props.href === 'string') {
    return (
      <a {...(rest as React.AnchorHTMLAttributes<HTMLAnchorElement>)} className={cls}>
        {children}
      </a>
    );
  }
  return (
    <button type="button" {...(rest as React.ButtonHTMLAttributes<HTMLButtonElement>)} className={cls}>
      {children}
    </button>
  );
}
