"use client";

import { cn } from "@/lib/utils";
import { type ButtonHTMLAttributes, forwardRef } from "react";

export type ButtonVariant = "primary" | "neutral" | "danger" | "violet" | "ghost";
export type ButtonSize = "sm" | "md" | "lg" | "icon";

export interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: ButtonVariant;
  size?: ButtonSize;
  isLoading?: boolean;
}

const variantClasses: Record<ButtonVariant, string> = {
  primary:
    "bg-[#18a66b] text-[#ffffff] border-[#18a66b] hover:bg-[#0f8b58] active:bg-[#3fd08b] shadow-[0_8px_24px_rgba(86,227,159,0.16)]",
  neutral:
    "bg-[#f3f6f9] text-[#243342] border-[#cbd5e1] hover:bg-[#eef2f5] hover:border-[#aab8c7] active:bg-[#e3e9ef]",
  danger:
    "bg-[#fde8eb] text-[#ff8a96] border-[#f0aab5] hover:bg-[#351a22] active:bg-[#401d26]",
  violet:
    "bg-[#1e2d3d] text-[#18a66b] border-[#1e2d3d] hover:bg-[#243342] active:bg-[#2a3c50]",
  ghost:
    "bg-transparent text-[#5d6b7b] border-transparent hover:text-[#15202b] hover:bg-[#f3f6f9]",
};

const sizeClasses: Record<ButtonSize, string> = {
  sm: "px-2.5 py-1 text-xs",
  md: "px-4 py-2 text-sm",
  lg: "px-5 py-2.5 text-base",
  icon: "h-8 w-8 p-0",
};

export const Button = forwardRef<HTMLButtonElement, ButtonProps>(
  (
    {
      variant = "neutral",
      size = "md",
      isLoading = false,
      disabled,
      className,
      children,
      ...props
    },
    ref
  ) => {
    return (
      <button
        ref={ref}
        disabled={disabled || isLoading}
        className={cn(
          "inline-flex items-center justify-center gap-2 rounded-md border font-medium transition-colors select-none",
          "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#18a66b]/50 focus-visible:ring-offset-1 focus-visible:ring-offset-[#f7f9fc]",
          "disabled:opacity-40 disabled:cursor-not-allowed",
          variantClasses[variant],
          sizeClasses[size],
          className
        )}
        {...props}
      >
        {isLoading ? (
          <>
            <svg
              className="h-3.5 w-3.5 animate-spin"
              fill="none"
              viewBox="0 0 24 24"
            >
              <circle
                className="opacity-25"
                cx="12"
                cy="12"
                r="10"
                stroke="currentColor"
                strokeWidth="4"
              />
              <path
                className="opacity-75"
                fill="currentColor"
                d="M4 12a8 8 0 018-8v8H4z"
              />
            </svg>
            <span>{children}</span>
          </>
        ) : (
          children
        )}
      </button>
    );
  }
);

Button.displayName = "Button";
