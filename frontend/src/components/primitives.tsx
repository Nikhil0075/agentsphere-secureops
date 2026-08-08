/** Small shared building blocks. Kept in one file so the screens stay readable. */

import { useEffect, useRef, useState, type ReactNode } from "react";
import type { TriageLabel } from "../lib/api";

/* Severity tones. Each is a text/tint/border triple re-tuned for a white background — the
   dark-theme values measured below 4.5:1 once the surface went light. */
const LABEL_STYLE: Record<string, string> = {
  TruePositive: "bg-tp-soft text-tp border-tp-line",
  BenignPositive: "bg-bp-soft text-bp border-bp-line",
  FalsePositive: "bg-fp-soft text-fp border-fp-line",
};

const RISK_STYLE: Record<string, string> = {
  low: "bg-fp-soft text-fp border-fp-line",
  medium: "bg-bp-soft text-bp border-bp-line",
  high: "bg-tp-soft text-tp border-tp-line",
};

const VERDICT_STYLE: Record<string, string> = {
  accept: "bg-fp-soft text-fp border-fp-line",
  escalate: "bg-bp-soft text-bp border-bp-line",
  reject: "bg-tp-soft text-tp border-tp-line",
};

const EXTRA_STYLE: Record<string, string> = {
  info: "bg-info-soft text-info border-info-line",
  /* Only for the dark header band, where gold clears 8.8:1. Never on the light canvas. */
  brand: "bg-brand/15 text-brand border-brand/40",
};

export function Badge({
  children,
  tone = "neutral",
  className = "",
}: {
  children: ReactNode;
  tone?: string;
  className?: string;
}) {
  const style =
    LABEL_STYLE[tone] ??
    RISK_STYLE[tone] ??
    VERDICT_STYLE[tone] ??
    EXTRA_STYLE[tone] ??
    "bg-raised text-muted border-line";
  return (
    <span
      className={`inline-flex items-center gap-1 rounded-full border px-2.5 py-0.5 text-xs font-medium whitespace-nowrap ${style} ${className}`}
    >
      {children}
    </span>
  );
}

export function LabelBadge({ label }: { label: TriageLabel | string }) {
  const short =
    label === "TruePositive" ? "TP" : label === "BenignPositive" ? "BP" : label === "FalsePositive" ? "FP" : "?";
  return (
    <Badge tone={label}>
      <span className="font-bold">{short}</span>
      <span className="hidden opacity-75 sm:inline">{label}</span>
    </Badge>
  );
}

export function Card({
  title,
  subtitle,
  right,
  children,
  className = "",
  pad = true,
}: {
  title?: ReactNode;
  subtitle?: ReactNode;
  right?: ReactNode;
  children: ReactNode;
  className?: string;
  pad?: boolean;
}) {
  return (
    <section className={`rounded-2xl border border-line bg-surface ${className}`}>
      {(title || right) && (
        <header className="flex items-start justify-between gap-3 border-b border-line px-5 py-4">
          <div className="min-w-0">
            {title && (
              <h2 className="text-sm font-semibold tracking-[-0.01em] text-text">{title}</h2>
            )}
            {subtitle && <p className="mt-1 text-xs leading-relaxed text-muted">{subtitle}</p>}
          </div>
          {right && <div className="shrink-0">{right}</div>}
        </header>
      )}
      <div className={pad ? "p-5" : ""}>{children}</div>
    </section>
  );
}

export function PageIntro({
  eyebrow,
  title,
  description,
  actions,
}: {
  eyebrow: string;
  title: ReactNode;
  description: ReactNode;
  actions?: ReactNode;
}) {
  return (
    <section className="page-intro mb-5 overflow-hidden rounded-3xl px-6 py-7 sm:px-8 sm:py-9">
      <div className="flex flex-col justify-between gap-5 lg:flex-row lg:items-end">
        <div className="max-w-3xl">
          {/* Mono eyebrow: the reference uses monospace as its small-heading voice, which also
              distinguishes a scene label from the body copy beneath it without shouting. */}
          <div className="mono text-code uppercase tracking-[0.14em] text-primary">{eyebrow}</div>
          {/* Large and LIGHT. Weight 300 at −0.025em is the single most recognisable thing about
              the reference; it needs size to work, which is why it does not go below 32px. */}
          <h1 className="mt-2.5 text-display-sm text-text sm:text-display">{title}</h1>
          <p className="mt-4 max-w-2xl text-sm leading-6 text-muted">{description}</p>
        </div>
        {actions ? <div className="flex shrink-0 flex-wrap items-center gap-2">{actions}</div> : null}
      </div>
    </section>
  );
}

/**
 * Headline figure for the strip under the header.
 *
 * Deliberately larger than `Stat`: these are the numbers a judge should be able to read without
 * walking to the laptop.
 */
export function Kpi({
  label,
  value,
  hint,
  tone,
}: {
  label: string;
  value: ReactNode;
  hint?: ReactNode;
  tone?: "good" | "warn" | "bad";
}) {
  const colour =
    tone === "good" ? "text-fp" : tone === "warn" ? "text-bp" : tone === "bad" ? "text-tp" : "text-text";
  return (
    <div className="rounded-xl border border-line bg-surface px-4 py-3">
      <div className="text-3xs font-medium uppercase tracking-[0.12em] text-faint">{label}</div>
      {/* Display weight rather than bold: a large light figure reads as a headline number, a large
          bold one reads as an alert. The severity colours are what signal urgency here. */}
      <div className={`mt-1.5 text-display-sm leading-none ${colour}`}>{value}</div>
      {hint && <div className="mt-2 text-2xs leading-snug text-muted">{hint}</div>}
    </div>
  );
}

export function Stat({
  label,
  value,
  hint,
  tone,
}: {
  label: string;
  value: ReactNode;
  hint?: ReactNode;
  tone?: "good" | "warn" | "bad";
}) {
  const colour =
    tone === "good" ? "text-fp" : tone === "warn" ? "text-bp" : tone === "bad" ? "text-tp" : "text-text";
  return (
    <div className="rounded-xl bg-raised px-3.5 py-3">
      <div className="text-3xs font-medium uppercase tracking-[0.12em] text-faint">{label}</div>
      <div className={`mt-1.5 text-lg font-medium leading-none tracking-[-0.015em] ${colour}`}>
        {value}
      </div>
      {hint && <div className="mt-1.5 text-2xs leading-snug text-muted">{hint}</div>}
    </div>
  );
}

/** The filter row Queue and Provenance had each grown separately. */
export function Toolbar({ children }: { children: ReactNode }) {
  return <div className="flex flex-wrap items-center gap-2">{children}</div>;
}

export function SegmentedFilter<T extends string>({
  label,
  value,
  options,
  onChange,
}: {
  label: string;
  value: T;
  options: readonly { value: T; label: string }[];
  onChange: (value: T) => void;
}) {
  return (
    <div
      className="inline-flex rounded-xl border border-line bg-raised p-0.5"
      role="group"
      aria-label={label}
    >
      {options.map((option) => (
        <button
          key={option.value}
          type="button"
          aria-pressed={value === option.value}
          onClick={() => onChange(option.value)}
          className={`rounded-md px-2.5 py-1.5 text-2xs font-semibold transition-colors ${
            value === option.value
              ? "bg-surface text-primary"
              : "text-muted hover:text-text"
          }`}
        >
          {option.label}
        </button>
      ))}
    </div>
  );
}

export function Popover({
  label,
  trigger,
  children,
  active = false,
}: {
  label: string;
  trigger: ReactNode;
  children: ReactNode;
  active?: boolean;
}) {
  const [open, setOpen] = useState(false);
  const root = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!open) return;
    const closeOnOutside = (event: MouseEvent) => {
      if (!root.current?.contains(event.target as Node)) setOpen(false);
    };
    const closeOnEscape = (event: KeyboardEvent) => {
      if (event.key === "Escape") setOpen(false);
    };
    document.addEventListener("mousedown", closeOnOutside);
    document.addEventListener("keydown", closeOnEscape);
    return () => {
      document.removeEventListener("mousedown", closeOnOutside);
      document.removeEventListener("keydown", closeOnEscape);
    };
  }, [open]);

  return (
    <div ref={root} className="relative">
      <button
        type="button"
        aria-label={label}
        aria-haspopup="menu"
        aria-expanded={open}
        onClick={() => setOpen((current) => !current)}
        className={`rounded-lg px-3 py-2 text-xs font-semibold transition-colors ${
          active || open
            ? "bg-white/15 text-white"
            : "text-white/65 hover:bg-white/10 hover:text-white"
        }`}
      >
        {trigger}
      </button>
      {open ? (
        <div
          role="menu"
          onClick={() => setOpen(false)}
          className="floating-panel absolute right-0 top-[calc(100%+0.65rem)] z-40 w-80 rounded-2xl border border-line bg-surface p-2 text-text"
        >
          {children}
        </div>
      ) : null}
    </div>
  );
}

export function IconButton({
  label,
  children,
  onClick,
  active = false,
  disabled = false,
}: {
  label: string;
  children: ReactNode;
  onClick: () => void;
  active?: boolean;
  disabled?: boolean;
}) {
  return (
    <button
      type="button"
      aria-label={label}
      title={label}
      aria-pressed={active}
      disabled={disabled}
      onClick={onClick}
      className={`inline-flex h-8 min-w-8 items-center justify-center rounded-lg border px-2 text-xs font-bold transition-colors duration-100 disabled:cursor-not-allowed disabled:opacity-40 ${
        active
          ? "border-primary bg-primary text-white"
          : "border-line bg-surface text-muted hover:border-primary-line hover:bg-primary-soft hover:text-primary"
      }`}
    >
      {children}
    </button>
  );
}

export function TextInput({
  value,
  onChange,
  placeholder,
  label = placeholder,
  className = "",
}: {
  value: string;
  onChange: (v: string) => void;
  placeholder?: string;
  label?: string;
  className?: string;
}) {
  return (
    <input
      value={value}
      onChange={(e) => onChange(e.target.value)}
      placeholder={placeholder}
      aria-label={label}
      className={`rounded-lg border border-line bg-surface px-3 py-1.5 text-xs text-text placeholder:text-faint focus:border-primary focus:outline-none focus:ring-2 focus:ring-primary/15 ${className}`}
    />
  );
}

export function Button({
  children,
  onClick,
  disabled,
  variant = "secondary",
  className = "",
}: {
  children: ReactNode;
  onClick?: () => void;
  disabled?: boolean;
  variant?: "primary" | "secondary" | "danger";
  className?: string;
}) {
  const style =
    variant === "primary"
      ? "bg-primary text-white hover:bg-primary-hover"
      : variant === "danger"
        ? "border border-tp-line bg-tp-soft text-tp hover:bg-tp-line/40"
        : "border border-line bg-surface text-text hover:bg-raised";
  return (
    <button
      type="button"
      onClick={onClick}
      disabled={disabled}
      className={`rounded-md px-3.5 py-2 text-xs font-semibold transition-colors duration-100 disabled:cursor-not-allowed disabled:opacity-40 ${style} ${className}`}
    >
      {children}
    </button>
  );
}

export function Hash({ value, chars = 18 }: { value: string; chars?: number }) {
  const [copied, setCopied] = useState(false);
  if (!value) return <span className="text-faint">—</span>;
  const legacyCopy = () => {
    const field = document.createElement("textarea");
    field.value = value;
    field.style.position = "fixed";
    field.style.opacity = "0";
    document.body.appendChild(field);
    field.select();
    const succeeded = document.execCommand("copy");
    field.remove();
    return succeeded;
  };
  const copy = async () => {
    try {
      if (navigator.clipboard?.writeText) {
        await navigator.clipboard.writeText(value);
      } else if (!legacyCopy()) throw new Error("copy unavailable");
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1200);
    } catch {
      if (legacyCopy()) {
        setCopied(true);
        window.setTimeout(() => setCopied(false), 1200);
      } else {
        setCopied(false);
      }
    }
  };
  return (
    <button
      type="button"
      onClick={() => void copy()}
      className="mono rounded text-left text-xs text-muted transition hover:text-primary focus:outline-none focus:ring-2 focus:ring-primary/20"
      title={copied ? "Copied" : `Copy ${value}`}
      aria-label={copied ? "Hash copied" : "Copy hash"}
    >
      {value.length > chars + 4 ? `${value.slice(0, chars)}…${value.slice(-4)}` : value}
      {copied ? <span className="ml-1 font-sans text-3xs text-fp">copied</span> : null}
    </button>
  );
}

/**
 * Anchored digest beside recomputed digest.
 *
 * Extracted from the Workflow integrity card because the Proof screen now owns it. Showing both
 * side by side is the point: a lone "invalid" badge asks the audience to take the verdict on
 * faith, whereas two visibly different hashes are the evidence itself.
 */
export function HashPair({
  label,
  anchored,
  recomputed,
  valid,
}: {
  label: string;
  anchored: string;
  recomputed: string;
  valid: boolean | null;
}) {
  const differs = valid === false;
  return (
    <div className="grid grid-cols-[7rem_1fr] gap-x-4 gap-y-1 border-b border-line py-3 last:border-b-0 sm:grid-cols-[7rem_1fr_1fr]">
      <div className="text-xs font-medium text-muted">{label}</div>
      <div className="min-w-0">
        <div className="text-3xs uppercase tracking-wider text-faint">Anchored</div>
        <div className="truncate" title={anchored}>
          <Hash value={anchored} chars={28} />
        </div>
      </div>
      <div className="min-w-0">
        <div className="text-3xs uppercase tracking-wider text-faint">Recomputed</div>
        <div className={`truncate ${differs ? "font-semibold text-tp" : "text-text"}`} title={recomputed}>
          <Hash value={recomputed} chars={28} />
        </div>
      </div>
    </div>
  );
}

export function CheckRow({ check }: { check: { policy_id: string; passed: boolean; detail: string } }) {
  return (
    <li className="flex items-start gap-2.5 py-1.5 text-xs">
      <span
        className={`mt-px inline-block w-10 shrink-0 rounded-md py-0.5 text-center text-3xs font-bold ${
          check.passed ? "bg-fp-soft text-fp" : "bg-tp-soft text-tp"
        }`}
      >
        {check.passed ? "PASS" : "FAIL"}
      </span>
      <span className="mono shrink-0 text-faint">{check.policy_id}</span>
      <span className="text-muted">{check.detail}</span>
    </li>
  );
}

export function Spinner({ label }: { label?: string }) {
  return (
    <div className="flex items-center gap-2.5 py-2 text-sm text-muted">
      <span className="inline-block h-3.5 w-3.5 animate-spin rounded-full border-2 border-line border-t-primary" />
      {label}
    </div>
  );
}

export function Skeleton({ className = "h-4" }: { className?: string }) {
  return <div aria-hidden="true" className={`skeleton rounded-lg bg-raised ${className}`} />;
}

export function Empty({ children }: { children: ReactNode }) {
  return <p className="py-8 text-center text-sm text-muted">{children}</p>;
}

export function ErrorNote({ children }: { children: ReactNode }) {
  return (
    <div className="mt-3 rounded-lg border border-tp-line bg-tp-soft px-3 py-2 text-sm text-tp">
      {children}
    </div>
  );
}

/** Used wherever WitFoo data or a dataset caveat needs to sit next to a number. */
export function Note({ children, tone = "info" }: { children: ReactNode; tone?: "info" | "warn" }) {
  const style =
    tone === "warn" ? "border-bp-line bg-bp-soft text-bp" : "border-info-line bg-info-soft text-info";
  return (
    <p className={`rounded-lg border px-3.5 py-2.5 text-xs leading-relaxed ${style}`}>{children}</p>
  );
}
