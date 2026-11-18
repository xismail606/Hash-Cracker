// Run card: retention acknowledgement, plaintext-store opt-in, start/pause/
// resume/cancel controls, and the run error banner.

import { Play, Square } from "lucide-react";

import CardHeader from "./Card.jsx";

export function RunCard({
  acknowledged,
  onAcknowledgedChange,
  storePlaintext,
  onStorePlaintextChange,
  startAudit,
  starting,
  canAudit,
  running,
  job,
  pauseAudit,
  resumeAudit,
  cancelAudit,
  error,
}) {
  return (
    <section className="card" aria-labelledby="step-run">
      <CardHeader id="step-run" icon={<Play size={15} />} title="Run" />
      <div className="px-5 py-4">
        <label className="flex cursor-pointer items-start gap-3 text-sm leading-relaxed text-text-muted">
          <input
            type="checkbox"
            className="mt-1 accent-accent"
            checked={acknowledged}
            onChange={(e) => onAcknowledgedChange(e.target.checked)}
            disabled={running}
          />
          <span>
            If this audit finds a match, the recovered plaintext and its target
            hash will be saved to the{" "}
            <strong className="font-bold text-text">local SQLite history</strong>{" "}
            on this machine as sensitive credential data.
          </span>
        </label>
        <label className="mt-3 flex cursor-pointer items-start gap-3 text-sm leading-relaxed text-text-muted">
          <input
            type="checkbox"
            className="mt-1 accent-accent"
            checked={storePlaintext}
            onChange={(e) => onStorePlaintextChange(e.target.checked)}
            disabled={running}
          />
          <span>
            Store the recovered plaintext in local history on a match
            (off by default; tick to keep the plaintext/hash pair).
          </span>
        </label>
        <div className="mt-4 flex gap-3">
          <button className="btn-primary px-6 py-3 text-sm" onClick={startAudit} disabled={!canAudit}>
            {starting ? "Starting…" : "Start audit"}
          </button>
          {running && (
            <button className="btn-secondary flex items-center gap-2 px-6 py-3 text-sm" onClick={pauseAudit}>
              <Square size={14} />
              Pause
            </button>
          )}
          {job && job.state === "paused" && (
            <button className="btn-primary flex items-center gap-2 px-6 py-3 text-sm" onClick={resumeAudit}>
              <Play size={14} />
              Resume
            </button>
          )}
          {(running || job?.state === "paused") && (
            <button className="btn-secondary flex items-center gap-2 px-6 py-3 text-sm" onClick={cancelAudit}>
              <Square size={14} />
              Cancel run
            </button>
          )}
        </div>
        {error && (
          <p className="mt-4 rounded-xl border border-danger/40 bg-danger/10 px-3 py-2 text-sm text-danger">
            {error}
          </p>
        )}
      </div>
    </section>
  );
}

export default RunCard;
