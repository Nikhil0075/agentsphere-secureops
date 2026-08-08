import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

const apiMock = vi.hoisted(() => ({ queryIncidents: vi.fn() }));
vi.mock("../src/lib/api", () => ({ api: apiMock }));

import { Queue } from "../src/pages/Queue";

const baseRow = {
  label: "TruePositive",
  split: "val",
  risk_score: 0.91,
  alert_count: 5,
  evidence_count: 8,
  top_category: "InitialAccess",
  top_detector: "1",
  top_alert_title: "Demo alert",
  max_suspicion_level: "Suspicious",
  mitre_techniques: "T1078",
  first_seen: "2026-08-06T00:00:00Z",
  is_showcase: true,
  demo_rank: null as number | null,
  demo_role: "",
  baseline_label: "TruePositive",
  baseline_confidence: 0.88,
};

const row = { ...baseRow, incident_id: "INC-DEMO" };

const page = {
  items: [row], total: 1, limit: 25, offset: 0,
  sort_by: "risk", sort_dir: "desc", facets: { categories: ["InitialAccess"], suspicions: ["Suspicious"] },
};

/** Six ranked cases, the shape the arc query returns. */
const arcItems = Array.from({ length: 6 }, (_, index) => ({
  ...baseRow,
  incident_id: `INC-CASE${index + 1}`,
  demo_rank: index + 1,
  demo_role: `role_${index + 1}`,
  risk_score: 0.9 - index * 0.1,
}));

/**
 * The table query and the arc query hit the same function, so they are told apart by `demo_only`.
 * Making the table return a *single* row while the arc returns six is what proves "Next demo"
 * walks the arc rather than the visible page.
 */
const routeByQuery = (tableItems = [row]) =>
  apiMock.queryIncidents.mockImplementation((params: Record<string, unknown>) => {
    if (params.demo_only && params.limit === 6) {
      return Promise.resolve({
        items: arcItems, total: 6, limit: 6, offset: 0,
        sort_by: "demo_rank", sort_dir: "asc", facets: { categories: [], suspicions: [] },
      });
    }
    return Promise.resolve({ ...page, items: tableItems, total: tableItems.length });
  });

describe("queue controls", () => {
  beforeEach(() => {
    apiMock.queryIncidents.mockReset();
    apiMock.queryIncidents.mockResolvedValue(page);
  });

  it("filters the complete queue and switches between the pool and the arc", async () => {
    const user = userEvent.setup();
    render(<Queue selected={null} onSelect={vi.fn()} />);
    await screen.findByText("INC-DEMO");

    await user.click(screen.getByRole("button", { name: "Showcase" }));
    await waitFor(() => expect(apiMock.queryIncidents).toHaveBeenLastCalledWith(
      expect.objectContaining({ showcase_only: true }),
    ));

    await user.type(screen.getByRole("textbox", { name: "Search incident or alert" }), "demo");
    await waitFor(() => expect(apiMock.queryIncidents).toHaveBeenLastCalledWith(
      expect.objectContaining({ search: "demo", showcase_only: true }),
    ), { timeout: 1000 });

    await user.click(screen.getByRole("button", { name: "Sort by Risk" }));
    await waitFor(() => expect(apiMock.queryIncidents).toHaveBeenLastCalledWith(
      expect.objectContaining({ sort_by: "risk", sort_dir: "asc" }),
    ));
  });

  it("requests the arc in rank order on the demo tab", async () => {
    const user = userEvent.setup();
    routeByQuery();
    render(<Queue selected={null} onSelect={vi.fn()} />);
    await screen.findByText("INC-DEMO");

    await user.click(screen.getByRole("button", { name: /Demo arc/ }));
    await waitFor(() => expect(apiMock.queryIncidents).toHaveBeenLastCalledWith(
      expect.objectContaining({ demo_only: true, sort_by: "demo_rank", sort_dir: "asc", limit: 6 }),
    ));
  });

  it("Next demo walks the whole arc and wraps, not just the visible page", async () => {
    // The regression this guards: the walk used to iterate the paginated table rows, so with a
    // one-row page it would re-select that single row forever and never reach cases 2..6.
    const user = userEvent.setup();
    const onSelect = vi.fn();
    routeByQuery();

    render(<Queue selected="INC-CASE6" onSelect={onSelect} />);
    await screen.findByText("INC-DEMO");
    await user.click(screen.getByRole("button", { name: /Demo arc/ }));

    const nextDemo = await screen.findByRole("button", { name: /Next demo/ });
    await user.click(nextDemo);
    expect(onSelect).toHaveBeenLastCalledWith("INC-CASE1");
  });

  it("Next demo starts at case 1 when nothing on the arc is selected", async () => {
    const user = userEvent.setup();
    const onSelect = vi.fn();
    routeByQuery();

    render(<Queue selected={null} onSelect={onSelect} />);
    await screen.findByText("INC-DEMO");
    await user.click(screen.getByRole("button", { name: /Demo arc/ }));

    await user.click(await screen.findByRole("button", { name: /Next demo/ }));
    expect(onSelect).toHaveBeenLastCalledWith("INC-CASE1");
  });

  it("badges an arc row with its case number", async () => {
    routeByQuery([{ ...row, demo_rank: 3, demo_role: "baseline_disagreement" }]);
    render(<Queue selected={null} onSelect={vi.fn()} />);

    const badge = await screen.findByTitle(/Demo case 3/);
    expect(badge).toHaveTextContent("3");
  });

  it("opens a ticket with the keyboard", async () => {
    const user = userEvent.setup();
    const onSelect = vi.fn();
    render(<Queue selected={null} onSelect={onSelect} />);
    const ticket = await screen.findByRole("row", { name: /INC-DEMO/ });

    ticket.focus();
    await user.keyboard("{Enter}");
    expect(onSelect).toHaveBeenCalledWith("INC-DEMO");
  });
});
