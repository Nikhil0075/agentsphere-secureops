import { useEffect, useState, type ReactNode } from "react";

/**
 * Shared chart plumbing.
 *
 * Two rules everything here exists to enforce:
 *
 * 1. **No hex ever appears in a chart.** Colours are read from the CSS custom properties in
 *    `index.css`, so the charts and the rest of the UI cannot drift. The existing
 *    `ProvenanceGraphView` hardcoded five hexes and is the cautionary example.
 * 2. **No animation under reduced motion.** The global `@media (prefers-reduced-motion)` block
 *    clamps CSS transitions, but Recharts animates in JavaScript and ignores it entirely.
 */

export type Token =
  | "tp"
  | "bp"
  | "fp"
  | "info"
  | "primary"
  | "primaryLine"
  | "line"
  | "muted"
  | "faint"
  | "surface"
  | "raised"
  | "text";

const VAR: Record<Token, string> = {
  tp: "--color-tp",
  bp: "--color-bp",
  fp: "--color-fp",
  info: "--color-info",
  primary: "--color-primary",
  primaryLine: "--color-primary-line",
  line: "--color-line",
  muted: "--color-muted",
  faint: "--color-faint",
  surface: "--color-surface",
  raised: "--color-raised",
  text: "--color-text",
};

/**
 * Fallbacks matter: jsdom returns "" from getPropertyValue, and Recharts renders `fill=""` rather
 * than failing, which produces invisible charts in tests and no error to explain them.
 */
const FALLBACK: Record<Token, string> = {
  tp: "#b42318",
  bp: "#b54708",
  fp: "#027a48",
  info: "#175cd3",
  primary: "#172b76",
  primaryLine: "#c3cdea",
  line: "#dbe5ed",
  muted: "#46527f",
  faint: "#586490",
  surface: "#ffffff",
  raised: "#e4ebf2",
  text: "#131c42",
};

export function useThemeTokens(): Record<Token, string> {
  const [tokens, setTokens] = useState<Record<Token, string>>(FALLBACK);

  useEffect(() => {
    const style = getComputedStyle(document.documentElement);
    const resolved = {} as Record<Token, string>;
    for (const key of Object.keys(VAR) as Token[]) {
      resolved[key] = style.getPropertyValue(VAR[key]).trim() || FALLBACK[key];
    }
    setTokens(resolved);
  }, []);

  return tokens;
}

/** Mirrors the check `Workflow.focusStage` makes, so motion behaviour is consistent app-wide. */
export function useReducedMotion(): boolean {
  const [reduced, setReduced] = useState(false);

  useEffect(() => {
    const query = window.matchMedia?.("(prefers-reduced-motion: reduce)");
    if (!query) return;
    setReduced(query.matches);
    const listener = (event: MediaQueryListEvent) => setReduced(event.matches);
    query.addEventListener?.("change", listener);
    return () => query.removeEventListener?.("change", listener);
  }, []);

  return reduced;
}

/** The semantic colour for a triage label, verdict or risk level. */
export function toneFor(tokens: Record<Token, string>, value: string): string {
  const key = value.toLowerCase();
  if (key.includes("truepositive") || key === "reject" || key === "high") return tokens.tp;
  if (key.includes("benignpositive") || key === "escalate" || key === "medium") return tokens.bp;
  if (key.includes("falsepositive") || key === "accept" || key === "low") return tokens.fp;
  return tokens.primary;
}

/**
 * A titled, captioned chart box.
 *
 * `min-w-0` is load-bearing in two places: here, and on every grid cell that holds one. Without it
 * CSS grid's automatic minimum sizing lets a ResponsiveContainer push the page wider than the
 * viewport, which is the single most likely cause of horizontal overflow at 1024px.
 */
export function ChartFrame({
  title,
  caption,
  height = 220,
  children,
  right,
}: {
  title: string;
  caption?: ReactNode;
  height?: number;
  children: ReactNode;
  right?: ReactNode;
}) {
  return (
    <div className="min-w-0">
      <div className="flex flex-wrap items-baseline justify-between gap-2">
        <h4 className="text-2xs font-semibold uppercase tracking-wider text-faint">{title}</h4>
        {right}
      </div>
      <div className="mt-2 min-w-0" style={{ height }}>
        {children}
      </div>
      {caption && (
        <p className="mt-1.5 text-2xs leading-relaxed text-faint">{caption}</p>
      )}
    </div>
  );
}

/** Tooltip styled to match `Card` rather than Recharts' default white box with a grey border. */
export function chartTooltipStyle(tokens: Record<Token, string>) {
  return {
    contentStyle: {
      background: tokens.surface,
      border: `1px solid ${tokens.line}`,
      borderRadius: "0.75rem",
      fontSize: "11px",
      boxShadow: "0 4px 16px rgb(16 24 40 / 0.08)",
    },
    labelStyle: { color: tokens.text, fontWeight: 600 },
    itemStyle: { color: tokens.muted },
  };
}

export function axisProps(tokens: Record<Token, string>) {
  return {
    tick: { fontSize: 11, fill: tokens.muted },
    tickLine: false,
    axisLine: { stroke: tokens.line },
  };
}

export function gridProps(tokens: Record<Token, string>) {
  return { strokeDasharray: "3 3", vertical: false, stroke: tokens.line };
}
