import type { HTMLAttributes, ReactNode, Ref } from 'react';

export function Notice({
  tone = 'info',
  title,
  children,
  className,
  ref,
  ...rest
}: {
  tone?: 'info' | 'error';
  title?: string;
  children?: ReactNode;
  ref?: Ref<HTMLDivElement>;
} & Omit<HTMLAttributes<HTMLDivElement>, 'role'>) {
  const classes = ['notice', `notice-${tone}`, className].filter(Boolean).join(' ');
  return (
    <div ref={ref} {...rest} className={classes} role={tone === 'error' ? 'alert' : 'status'}>
      {title ? <p className="notice-title">{title}</p> : null}
      {children ? <div className="notice-body">{children}</div> : null}
    </div>
  );
}
