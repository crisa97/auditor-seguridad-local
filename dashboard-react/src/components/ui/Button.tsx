import { type ButtonHTMLAttributes, forwardRef } from 'react';
import { cn } from '@/utils/helpers';

interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: 'primary' | 'secondary' | 'danger' | 'ghost';
  size?: 'sm' | 'md' | 'lg';
  isLoading?: boolean;
}

export const Button = forwardRef<HTMLButtonElement, ButtonProps>(
  (
    {
      className,
      variant = 'primary',
      size = 'md',
      isLoading = false,
      disabled,
      children,
      ...props
    },
    ref
  ) => {
    return (
      <button
        ref={ref}
        className={cn('btn', `btn-${variant}`, `btn-${size}`, className)}
        disabled={disabled || isLoading}
        {...props}
      >
        {isLoading && <span className="spinner-sm" aria-label="Cargando" />}
        {children}
      </button>
    );
  }
);

Button.displayName = 'Button';
