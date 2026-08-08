import { Badge, Card, Empty } from "../primitives";

interface Case {
  name: string;
  passed: boolean;
  detail: string;
}

/**
 * The end-to-end rehearsal sweep as a pass/fail strip.
 *
 * Every case is a real workflow or a real assertion against the policy engine — not a unit test.
 * It is the check run cold three times before demoing, so showing it here is showing the thing the
 * demo actually rests on.
 */
export function RehearsalStrip({ rehearsal }: { rehearsal?: Record<string, any> }) {
  const cases: Case[] = rehearsal?.cases ?? [];

  if (!cases.length) {
    return (
      <Card title="End-to-end rehearsal" subtitle="The pre-demo sweep.">
        <Empty>
          Not run yet. <span className="mono">python scripts/rehearse.py</span> exercises the full
          chain, the policy gate and the tamper round trip.
        </Empty>
      </Card>
    );
  }

  const passed = rehearsal?.passed ?? cases.filter((c) => c.passed).length;
  const total = rehearsal?.total ?? cases.length;
  const clean = passed === total;

  return (
    <Card
      title="End-to-end rehearsal"
      subtitle={`${rehearsal?.backend ?? "unknown"} backend · mean workflow latency ${Math.round(
        rehearsal?.mean_latency_ms ?? 0,
      ).toLocaleString()}ms`}
      right={
        <Badge tone={clean ? "low" : "high"}>
          {passed} / {total} passed
        </Badge>
      }
    >
      <div className="flex flex-wrap gap-1">
        {cases.map((item) => (
          <span
            key={item.name}
            title={`${item.name} — ${item.detail}`}
            className={`h-6 min-w-6 rounded px-1.5 text-center text-3xs font-semibold leading-6 ${
              item.passed ? "bg-fp-soft text-fp" : "bg-tp-soft text-tp"
            }`}
          >
            {item.passed ? "✓" : "✗"}
          </span>
        ))}
      </div>

      <details className="mt-3">
        <summary className="cursor-pointer text-2xs text-faint">All {total} cases</summary>
        <ul className="mt-1.5 space-y-1">
          {cases.map((item) => (
            <li key={item.name} className="flex flex-wrap items-baseline gap-2 text-2xs">
              <span
                className={`shrink-0 rounded px-1 text-4xs font-semibold ${
                  item.passed ? "bg-fp-soft text-fp" : "bg-tp-soft text-tp"
                }`}
              >
                {item.passed ? "PASS" : "FAIL"}
              </span>
              <span className="mono shrink-0 text-muted">{item.name}</span>
              <span className="min-w-0 text-faint">{item.detail}</span>
            </li>
          ))}
        </ul>
      </details>
    </Card>
  );
}
