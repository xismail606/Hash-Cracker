// Shared constants and helpers for the dashboard cards.

// Labels and tones come from the engine's status vocabulary; a status the
// dashboard does not know falls back to the raw identifier and a neutral tone.
export const STATUS_LABELS = {
  match: "Match",
  no_match: "No match",
  budget_exhausted: "Budget exhausted",
  paused: "Paused",
  cancelled: "Cancelled",
  interrupted: "Interrupted",
  invalid_input: "Invalid input",
  storage_error: "Storage error",
};

export const STATUS_TONE = {
  match: "text-success border-success/40 bg-success/10",
  no_match: "text-text-muted border-border bg-surface-raised",
  budget_exhausted: "text-warning border-warning/40 bg-warning/10",
  cancelled: "text-warning border-warning/40 bg-warning/10",
  interrupted: "text-danger border-danger/40 bg-danger/10",
  invalid_input: "text-danger border-danger/40 bg-danger/10",
  storage_error: "text-danger border-danger/40 bg-danger/10",
};

export const isSalted = (name) =>
  name.endsWith("_pass_salt") || name.endsWith("_salt_pass");

export const labelClass =
  "mb-1.5 block text-[10px] font-bold section-label text-text-muted";

export async function apiFetch(path, options = {}) {
  const response = await fetch(path, { credentials: "same-origin", ...options });
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) {
    const message =
      payload.error ||
      (response.status === 404
        ? "API route not found — this page is not being served by the Flask backend. Run `python -m password_audit serve` and open the printed http://127.0.0.1 URL."
        : `Request failed (${response.status})`);
    throw new Error(message);
  }
  return payload;
}
