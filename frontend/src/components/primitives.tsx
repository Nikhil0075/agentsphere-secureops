/** Small shared building blocks. Kept in one file so the screens stay readable. */

import type { ReactNode } from "react";
import type { TriageLabel } from "../lib/api";

const LABEL_STYLE: Record<string, string> = {
  TruePositive: "bg-tp/15 text-tp border-tp/30",
  BenignPositive: "bg-bp/15 text-bp border-bp/30",
  FalsePositive: "bg-fp/15 text-fp border-fp/30",
};

const RISK_STYLE: Record<string, string> = {
  low: "bg-fp/15 text-fp border-fp/30",
  medium: "bg-bp/15 text-bp border-bp/30",
  high: "bg-tp/15 text-tp border-tp/30",
};

const VERDICT_STYLE: Record<string, string> = {
  accept: "bg-fp/15 text-fp border-fp/30",
  escalate: "bg-bp/15 text-bp border-bp/30",
  reject: "bg-tp/15 text-tp border-tp/30",
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
    "bg-ink-700/50 text-ink-300 border-ink-600";
  return (
    <span
      className={`inline-flex items-center gap-1 rounded border px-2 py-0.5 text-xs font-medium whitespace-nowrap ${style} ${className}`}
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
      <span className="hidden sm:inline opacity-70">{label}</span>
    </Badge>
  );
}

export function Card({
  title,
  subtitle,
  right,
  children,
  className = "",
}: {
  title?: ReactNode;
  subtitle?: ReactNode;
  right?: ReactNode;
  children: ReactNode;
  className?: string;
}) {
  return (
    <section
      className={`rounded-lg border border-ink-800 bg-ink-900 ${className}`}
    >
      {(title || right) && (
        <header className="flex items-start justify-between gap-3 border-b border-ink-800 px-4 py-3">
          <div className="min-w-0">
            {title && <h2 className="text-sm font-semibold text-ink-200">{title}</h2>}
            {subtitle && <p className="mt-0.5 text-xs text-ink-400">{subtitle}</p>}
          </div>
          {right}
        </header>
      )}
      <div className="p-4">{children}</div>
    </section>
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
    tone === "good" ? "text-fp" : tone === "warn" ? "text-bp" : tone === "bad" ? "text-tp" : "text-ink-200";
  return (
    <div className="rounded-md border border-ink-800 bg-ink-850 px-3 py-2">
      <div className="text-[11px] uppercase tracking-wide text-ink-400">{label}</div>
      <div className={`mt-0.5 text-lg font-semibold ${colour}`}>{value}</div>
      {hint && <div className="text-[11px] text-ink-400">{hint}</div>}
    </div>
  );
}

export function Hash({ value, chars = 18 }: { value: string; chars?: number }) {
  if (!value) return <span className="text-ink-400">—</span>;
  return (
    <span className="mono text-xs text-ink-300" title={value}>
      {value.length > chars + 4 ? `${value.slice(0, chars)}…${value.slice(-4)}` : value}
    </span>
  );
}

export function CheckRow({ check }: { check: { policy_id: string; passed: boolean; detail: string } }) {
  return (
    <li className="flex items-start gap-2 py-1 text-xs">
      <span
        className={`mt-0.5 inline-block h-4 w-9 shrink-0 rounded text-center text-[10px] font-bold leading-4 ${
          check.passed ? "bg-fp/20 text-fp" : "bg-tp/20 text-tp"
        }`}
      >
        {check.passed ? "PASS" : "FAIL"}
      </span>
      <span className="mono shrink-0 text-ink-400">{check.policy_id}</span>
      <span className="text-ink-300">{check.detail}</span>
    </li>
  );
}

export function Spinner({ label }: { label?: string }) {
  return (
    <div className="flex items-center gap-2 text-sm text-ink-400">
      <span className="inline-block h-3 w-3 animate-spin rounded-full border-2 border-ink-600 border-t-accent" />
      {label}
    </div>
  );
}

export function Empty({ children }: { children: ReactNode }) {
  return <p className="py-6 text-center text-sm text-ink-400">{children}</p>;
}

export function ErrorNote({ children }: { children: ReactNode }) {
  return (
    <div className="rounded border border-tp/30 bg-tp/10 px-3 py-2 text-sm text-tp">{children}</div>
  );
}
