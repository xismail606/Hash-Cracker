import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, test, vi } from "vitest";

import AuditDashboard from "./AuditDashboard.jsx";

const FORMATS_PAYLOAD = {
  algorithms: [{ name: "md5", label: "MD5 (server)", kind: "fast" }],
  labels: { md5: "MD5 (server)" },
  salted_by_length: {},
  charset_presets: [{ name: "lower", label: "lowercase a-z" }],
  rules_presets: [{ name: "none", label: "Server-only no-rules label" }],
  max_workers: 8,
  default_workers: 4,
  hard_max_candidates: 10_000_000,
  default_budget: 1_000_000,
};

function jsonResponse(body) {
  return Promise.resolve({
    ok: true,
    status: 200,
    json: () => Promise.resolve(body),
  });
}

function installFetch({ identify } = {}) {
  const fetchMock = vi.fn((url) => {
    const target = String(url);
    if (target.includes("/api/session")) return jsonResponse({ csrf_token: "tok" });
    if (target.includes("/api/formats")) return jsonResponse(FORMATS_PAYLOAD);
    if (target.includes("/api/history")) {
      return jsonResponse({ records: [], encrypted_count: 0 });
    }
    if (target.includes("/api/identify") && identify) return jsonResponse(identify);
    return jsonResponse({});
  });
  vi.stubGlobal("fetch", fetchMock);
  return fetchMock;
}

describe("AuditDashboard", () => {
  beforeEach(() => {
    vi.unstubAllGlobals();
  });

  test("renders the audit form and blocks the start button until acknowledged", async () => {
    installFetch();
    render(<AuditDashboard />);

    expect(await screen.findByText("Target hash")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /identify format/i })).toBeEnabled();
    expect(screen.getByRole("button", { name: /start audit/i })).toBeDisabled();
  });

  test("renders rule presets from the server registry, not local constants", async () => {
    installFetch();
    render(<AuditDashboard />);

    expect(
      await screen.findByRole("option", { name: "Server-only no-rules label" }),
    ).toBeInTheDocument();
  });

  test("uses server algorithm labels when identifying a hash", async () => {
    installFetch({
      identify: {
        valid: true,
        ambiguous: true,
        normalized: { length: 32 },
        compatible_algorithms: ["md5"],
      },
    });
    render(<AuditDashboard />);

    const user = userEvent.setup();
    await user.type(
      screen.getAllByPlaceholderText(/32-character/i)[0],
      "8743b52063cd84097a65d1633f5c74f5",
    );
    await user.click(
      screen.getAllByRole("button", { name: /identify format/i })[0],
    );

    expect((await screen.findAllByText("MD5 (server)")).length).toBeGreaterThan(0);
  });
});
