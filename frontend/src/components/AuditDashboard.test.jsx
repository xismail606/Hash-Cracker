import { render, screen, waitFor } from "@testing-library/react";
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

function installFetch({ identify, auditJob, history } = {}) {
  const calls = [];
  const fetchMock = vi.fn((url, options = {}) => {
    const target = String(url);
    if (target.includes("/api/session")) return jsonResponse({ csrf_token: "tok" });
    if (target.includes("/api/formats")) return jsonResponse(FORMATS_PAYLOAD);
    if (target.includes("/api/history")) {
      return jsonResponse(
        history ?? { records: [], encrypted_count: 0, sensitive_note: "" },
      );
    }
    if (target.includes("/api/identify") && identify) return jsonResponse(identify);
    if (target.endsWith("/api/audits") && options.method === "POST") {
      calls.push({ url: target, options });
      return jsonResponse({ job_id: "abcdef1234567890" });
    }
    if (/\/api\/audits\/[a-z0-9]+$/.test(target)) {
      return jsonResponse(auditJob ?? { job_id: "abcdef1234567890", state: "running" });
    }
    calls.push({ url: target, options });
    return jsonResponse({});
  });
  vi.stubGlobal("fetch", fetchMock);
  fetchMock.calls = calls;
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

  test("a full brute-force start posts the expected multipart fields", async () => {
    const fetchMock = installFetch({
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
    await user.click(screen.getAllByRole("button", { name: /identify format/i })[0]);
    // Ambiguous shape: the operator must pick one algorithm explicitly.
    await user.click(await screen.findByRole("radio", { name: "MD5 (server)" }));
    await user.click(screen.getByRole("tab", { name: /brute force/i }));
    await user.click(screen.getByLabelText(/saved to the/i));

    const start = screen.getByRole("button", { name: /start audit/i });
    await waitFor(() => expect(start).toBeEnabled());
    await user.click(start);

    const startCall = fetchMock.calls.find(
      (call) => String(call.url).endsWith("/api/audits") && call.options.method === "POST",
    );
    expect(startCall).toBeDefined();
    const form = startCall.options.body;
    const field = (name) => form.get(name);
    expect(field("mode")).toBe("brute-force");
    expect(field("hash")).toBe("8743b52063cd84097a65d1633f5c74f5");
    expect(field("algorithm")).toBe("md5");
    expect(field("rules")).toBe("none");
    expect(field("charset")).toBe("lower");
    expect(field("min_length")).toBe("1");
    expect(field("max_length")).toBe("4");
    expect(field("max_candidates")).toBe("1000000");
    expect(field("acknowledge_retention")).toBe("true");
    // Plaintext withholding is the default.
    expect(field("store_plaintext")).toBe("false");
    expect(startCall.options.headers["X-CSRF-Token"]).toBe("tok");
  });

  test("a paused job shows a resume control and posts the resume request", async () => {
    const fetchMock = installFetch({
      identify: {
        valid: true,
        ambiguous: false,
        normalized: { length: 32 },
        compatible_algorithms: ["md5"],
      },
      auditJob: {
        job_id: "abcdef1234567890",
        state: "paused",
        attempts: 123456,
        budget: 1000000,
        workers: 2,
        elapsed_ms: 5000,
      },
    });
    render(<AuditDashboard />);
    const user = userEvent.setup();

    await user.type(
      screen.getAllByPlaceholderText(/32-character/i)[0],
      "8743b52063cd84097a65d1633f5c74f5",
    );
    await user.click(screen.getAllByRole("button", { name: /identify format/i })[0]);
    await user.click(await screen.findByRole("radio", { name: "MD5 (server)" }));
    await user.click(screen.getByRole("tab", { name: /brute force/i }));
    await user.click(screen.getByLabelText(/saved to the/i));

    const start = screen.getByRole("button", { name: /start audit/i });
    await waitFor(() => expect(start).toBeEnabled());
    await user.click(start);

    expect(
      await screen.findByText(/Job paused/i, undefined, { timeout: 3000 }),
    ).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: /resume/i }));

    const resumeCall = fetchMock.calls.find((call) =>
      String(call.url).endsWith("/api/audits/abcdef1234567890/resume"),
    );
    expect(resumeCall).toBeDefined();
    expect(resumeCall.options.method).toBe("POST");
  });

  test("renders history records including withheld plaintext markers", async () => {
    installFetch({
      history: {
        records: [
          {
            run_id: 1,
            started_at: "2026-11-18 10:00:00",
            status: "match",
            algorithm: "md5",
            mode: "dictionary",
            attempts: 4321,
            elapsed_ms: 1500,
            worker_count: 4,
            matched_plaintext: null,
            plaintext_withheld: true,
          },
          {
            run_id: 2,
            started_at: "2026-11-18 11:00:00",
            status: "no_match",
            algorithm: "sha256",
            mode: "brute-force",
            attempts: 10,
            elapsed_ms: 900,
            worker_count: 2,
            matched_plaintext: null,
            plaintext_withheld: false,
          },
        ],
        encrypted_count: 0,
        sensitive_note: "Records stay on this machine only.",
      },
    });
    render(<AuditDashboard />);

    expect(await screen.findByText("Records stay on this machine only.")).toBeInTheDocument();
    expect(await screen.findByText("Withheld")).toBeInTheDocument();
    expect(screen.getByText("4,321")).toBeInTheDocument();
    expect(screen.getByText("Match")).toBeInTheDocument();
    expect(screen.getByText("No match")).toBeInTheDocument();
  });
});
