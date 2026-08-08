import type { WorkflowResponse } from "../../lib/api";
import { Badge, Empty, LabelBadge, Note } from "../primitives";

/**
 * One typed renderer per agent.
 *
 * Detection, Correlation and Investigation used to render nothing at all — their full structured
 * output sat in the payload while the screen showed only a status row. Everything below is already
 * in the response; none of it required a backend change.
 */
export function AgentOutput({
  agent,
  result,
}: {
  agent: string;
  result: WorkflowResponse;
}) {
  switch (agent) {
    case "detection":
      return <DetectionView value={result.detection} />;
    case "correlation":
      return <CorrelationView value={result.correlation} />;
    case "investigation":
      return <InvestigationView value={result.investigation} />;
    case "triage":
      return <TriageView value={result.triage} />;
    case "remediation":
      return <RemediationView value={result.remediation} />;
    case "verifier":
      return <VerifierView value={result.verifier} />;
    default:
      return <Empty>No output recorded for this stage.</Empty>;
  }
}

/** A 0..1 score as a bar. Banded by the same semantics the rest of the app uses. */
function Meter({ value, label }: { value: number; label: string }) {
  const tone = value >= 0.66 ? "bg-tp" : value >= 0.33 ? "bg-bp" : "bg-fp";
  return (
    <div className="flex items-center gap-2">
      <span className="w-24 shrink-0 text-2xs uppercase tracking-wider text-faint">{label}</span>
      <div className="h-1.5 min-w-0 flex-1 overflow-hidden rounded-full bg-line">
        <div className={`h-full rounded-full ${tone}`} style={{ width: `${Math.min(100, value * 100)}%` }} />
      </div>
      <span className="mono w-10 shrink-0 text-right text-xs font-semibold text-text">
        {value.toFixed(2)}
      </span>
    </div>
  );
}

function Chip({ children }: { children: React.ReactNode }) {
  return (
    <span className="mono rounded bg-raised px-1.5 py-0.5 text-3xs text-muted">{children}</span>
  );
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div>
      <h4 className="text-2xs font-semibold uppercase tracking-wider text-faint">{title}</h4>
      <div className="mt-1.5">{children}</div>
    </div>
  );
}

function DetectionView({ value }: { value: WorkflowResponse["detection"] }) {
  if (!value) return <Empty>Detection produced no output.</Empty>;
  return (
    <div className="space-y-3">
      <Meter value={value.severity_score} label="Severity" />
      <Section title={`Suspicious entities (${value.suspicious_entities.length})`}>
        {value.suspicious_entities.length ? (
          <ul className="space-y-1.5">
            {value.suspicious_entities.map((entity, index) => (
              <li key={`${entity.entity_type}-${entity.value}-${index}`} className="min-w-0">
                <div className="flex flex-wrap items-center gap-1.5">
                  <Badge>{entity.entity_type}</Badge>
                  <span className="mono break-all text-xs text-text">{entity.value}</span>
                </div>
                <p className="mt-0.5 text-2xs leading-relaxed text-muted">{entity.reason}</p>
              </li>
            ))}
          </ul>
        ) : (
          <p className="text-2xs text-faint">None flagged.</p>
        )}
      </Section>
      <Section title="Initial reason">
        <p className="text-xs leading-relaxed text-muted">{value.initial_reason}</p>
      </Section>
    </div>
  );
}

function CorrelationView({ value }: { value: WorkflowResponse["correlation"] }) {
  if (!value) return <Empty>Correlation produced no output.</Empty>;
  return (
    <div className="space-y-3">
      <Section title={`Evidence bundle (${value.evidence_bundle.length})`}>
        <div className="flex flex-wrap gap-1">
          {value.evidence_bundle.map((id) => (
            <Chip key={id}>{id}</Chip>
          ))}
        </div>
      </Section>

      {value.relationships.length > 0 && (
        <Section title={`Relationships (${value.relationships.length})`}>
          <ul className="space-y-1">
            {value.relationships.map((rel, index) => (
              <li key={index} className="flex flex-wrap items-center gap-1.5 text-2xs">
                <span className="mono break-all text-text">{rel.source}</span>
                <span className="text-faint">—{rel.relation}→</span>
                <span className="mono break-all text-text">{rel.target}</span>
              </li>
            ))}
          </ul>
        </Section>
      )}

      {value.timeline.length > 0 && (
        <Section title={`Timeline (${value.timeline.length})`}>
          <ol className="space-y-2 border-l border-line pl-4">
            {value.timeline.map((event, index) => (
              <li key={index} className="relative min-w-0">
                <span
                  aria-hidden="true"
                  className="absolute -left-[21px] top-1.5 h-1.5 w-1.5 rounded-full bg-primary-line"
                />
                <div className="mono text-3xs text-faint">{event.timestamp}</div>
                <div className="text-2xs leading-relaxed text-muted">{event.description}</div>
                {event.evidence_id && <Chip>{event.evidence_id}</Chip>}
              </li>
            ))}
          </ol>
        </Section>
      )}

      {value.missing_information.length > 0 && (
        <Note tone="warn">
          <span className="font-medium">Gaps this agent reported:</span>{" "}
          {value.missing_information.join("; ")}. The Verifier reads these, and a confident call
          made over them fails a structural check.
        </Note>
      )}
    </div>
  );
}

function InvestigationView({ value }: { value: WorkflowResponse["investigation"] }) {
  if (!value) return <Empty>Investigation produced no output.</Empty>;
  return (
    <div className="space-y-3">
      <Section title={`Similar incidents (${value.similar_cases.length})`}>
        {value.similar_cases.length ? (
          <ul className="space-y-1.5">
            {value.similar_cases.map((similar) => (
              <li key={similar.incident_id} className="min-w-0">
                <Meter value={similar.similarity} label={similar.incident_id.slice(0, 12)} />
                <p className="mt-0.5 text-2xs leading-relaxed text-muted">
                  {similar.why_similar}
                </p>
              </li>
            ))}
          </ul>
        ) : (
          <p className="text-2xs text-faint">No sufficiently similar historical incident.</p>
        )}
        <p className="mt-1.5 text-3xs leading-relaxed text-faint">
          Retrieval returns similarity and text only — never the retrieved incident's label. Handing
          an agent "three similar incidents, all true positives" would leak the answer and void
          every metric.
        </p>
      </Section>

      {value.mitre_mapping.length > 0 && (
        <Section title={`MITRE ATT&CK (${value.mitre_mapping.length})`}>
          <ul className="space-y-1.5">
            {value.mitre_mapping.map((mapping) => (
              <li key={mapping.technique_id} className="min-w-0">
                <div className="flex flex-wrap items-center gap-1.5">
                  <Badge tone="info">{mapping.technique_id}</Badge>
                  <span className="text-xs text-text">{mapping.technique_name}</span>
                </div>
                <div className="mt-1 flex flex-wrap gap-1">
                  {mapping.supporting_evidence_ids.map((id) => (
                    <Chip key={id}>{id}</Chip>
                  ))}
                </div>
              </li>
            ))}
          </ul>
        </Section>
      )}

      <Section title="Summary">
        <p className="text-xs leading-relaxed text-muted">{value.investigation_summary}</p>
      </Section>
    </div>
  );
}

function TriageView({ value }: { value: WorkflowResponse["triage"] }) {
  if (!value) return <Empty>Triage produced no output.</Empty>;
  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center gap-3">
        <LabelBadge label={value.label} />
        <span className="text-xs text-muted">{(value.confidence * 100).toFixed(0)}% confidence</span>
      </div>
      <Section title="Rationale">
        <p className="text-xs leading-relaxed text-muted">{value.rationale}</p>
      </Section>
      <Section title={`Cited evidence (${value.supporting_evidence_ids.length})`}>
        <div className="flex flex-wrap gap-1">
          {value.supporting_evidence_ids.map((id) => (
            <Chip key={id}>{id}</Chip>
          ))}
        </div>
      </Section>
    </div>
  );
}

function RemediationView({ value }: { value: WorkflowResponse["remediation"] }) {
  if (!value) return <Empty>Remediation produced no output.</Empty>;
  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center gap-2">
        <span className="mono text-sm font-semibold text-text">{value.recommended_action}</span>
        <Badge tone={value.action_risk}>{value.action_risk} risk</Badge>
      </div>
      <Section title="Justification">
        <p className="text-xs leading-relaxed text-muted">{value.justification}</p>
      </Section>
      <Section title="Rollback plan">
        <p className="text-xs leading-relaxed text-muted">{value.rollback_plan}</p>
      </Section>
      <p className="text-3xs leading-relaxed text-faint">
        Simulated. Nothing here isolates a device, disables an account or touches a real system.
      </p>
    </div>
  );
}

function VerifierView({ value }: { value: WorkflowResponse["verifier"] }) {
  if (!value) return <Empty>Verifier produced no output.</Empty>;
  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center gap-2">
        <Badge tone={value.verdict}>{value.verdict}</Badge>
        {value.escalation_required && <Badge tone="medium">escalation required</Badge>}
      </div>

      {value.contradictions.length > 0 && (
        <Section title={`Contradictions (${value.contradictions.length})`}>
          <ul className="space-y-1">
            {value.contradictions.map((item, index) => (
              <li key={index} className="text-2xs leading-relaxed text-bp">
                → {item}
              </li>
            ))}
          </ul>
        </Section>
      )}

      {value.policy_checks.length > 0 && (
        <Section title={`Checks (${value.policy_checks.length})`}>
          <ul className="space-y-1">
            {value.policy_checks.map((check) => (
              <li key={check.policy_id} className="flex items-start gap-2 text-2xs">
                <span
                  className={`mt-0.5 shrink-0 rounded px-1 py-0.5 text-4xs font-semibold ${
                    check.passed ? "bg-fp-soft text-fp" : "bg-tp-soft text-tp"
                  }`}
                >
                  {check.passed ? "PASS" : "FAIL"}
                </span>
                <span className="mono shrink-0 text-muted">{check.policy_id}</span>
                <span className="min-w-0 text-muted">{check.detail}</span>
              </li>
            ))}
          </ul>
        </Section>
      )}

      {value.reasoning && (
        <Section title="Reasoning">
          <p className="text-xs leading-relaxed text-muted">{value.reasoning}</p>
        </Section>
      )}

      <p className="text-3xs leading-relaxed text-faint">
        Structural checks run on every backend, model output included. Measured: left to itself the
        live model rejected 40 of 40 real incidents citing evidence gaps, so the model may escalate
        freely but may only <em>reject</em> where a check actually failed.
      </p>
    </div>
  );
}
