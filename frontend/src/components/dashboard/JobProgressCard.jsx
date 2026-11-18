// Progress/result card for the active (or finished) job: live counters,
// ETA and budget progress, single-target match panel, hashlist per-target
// table, and the paused / error notices.

import { CircleCheck, Zap } from "lucide-react";

import CardHeader from "./Card.jsx";
import { STATUS_LABELS, STATUS_TONE, labelClass } from "./shared.js";

export function JobProgressCard({
  job,
  running,
  etaSeconds,
  budgetFraction,
  terminalCardClass,
  progressRef,
  label,
}) {
  return (
    <section
      ref={progressRef}
      className={`card ${terminalCardClass}`}
      aria-labelledby="step-progress"
    >
      <CardHeader
        id="step-progress"
        icon={<Zap size={15} />}
        title="Progress and result"
        right={
          <span className="mono text-xs text-text-muted">{job.job_id.slice(0, 8)}</span>
        }
      />
      <div className="px-5 py-4">
        <dl className="grid grid-cols-2 gap-3 sm:grid-cols-4">
          <div className="rounded-xl border border-border bg-surface-raised/40 px-3.5 py-3">
            <dt className={labelClass}>State</dt>
            <dd className="mt-1">
              {job.result ? (
                <span
                  className={`pill mono rounded-lg ${STATUS_TONE[job.result.status] || "text-text-muted border-border bg-surface-raised"}`}
                >
                  {STATUS_LABELS[job.result.status] || job.result.status}
                </span>
              ) : (
                <span className="mono flex items-center gap-2 text-sm capitalize text-text">
                  <span className="h-1.5 w-1.5 animate-pulse rounded-full bg-accent"></span>
                  {job.state}
                </span>
              )}
            </dd>
          </div>
          <div className="rounded-xl border border-border bg-surface-raised/40 px-3.5 py-3">
            <dt className={labelClass}>Attempts</dt>
            <dd className="mono mt-1 text-sm font-semibold text-text">
              {job.attempts.toLocaleString()}
            </dd>
          </div>
          <div className="rounded-xl border border-border bg-surface-raised/40 px-3.5 py-3">
            <dt className={labelClass}>Elapsed</dt>
            <dd className="mono mt-1 text-sm font-semibold text-text">
              {(job.elapsed_ms / 1000).toFixed(1)}s
            </dd>
          </div>
          <div className="rounded-xl border border-border bg-surface-raised/40 px-3.5 py-3">
            <dt className={labelClass}>Workers</dt>
            <dd className="mono mt-1 text-sm font-semibold text-text">{job.workers}</dd>
          </div>
        </dl>
        {etaSeconds !== null && running && (
          <p className="mono mt-3 text-xs text-text-muted">
            ETA ~{etaSeconds >= 60
              ? `${Math.floor(etaSeconds / 60)}m ${etaSeconds % 60}s`
              : `${etaSeconds}s`} at the current rate
          </p>
        )}
        {budgetFraction !== null && running && (
          <div className="mt-4">
            <div className="h-1.5 w-full overflow-hidden rounded-full bg-surface-raised">
              <div
                className={`h-full rounded-full bg-accent transition-[width] duration-500 ${running ? "progress-shimmer" : ""}`}
                style={{ width: `${budgetFraction * 100}%` }}
              />
            </div>
            <p className="mono mt-1.5 text-xs text-text-muted">
              {(budgetFraction * 100).toFixed(1)}% of {job.budget.toLocaleString()} candidate
              budget
            </p>
          </div>
        )}
        {job.result?.status === "match" && !job.result.targets && (
          <div className="mt-4 overflow-hidden rounded-2xl border border-success/30 bg-success/10">
            <div className="flex items-center gap-2.5 border-b border-success/20 px-4 py-3">
              <CircleCheck size={16} className="shrink-0 text-success" />
              <p className="text-sm font-bold text-success">
                {job.result.plaintext_withheld
                  ? "Match — plaintext withheld"
                  : "Match — sensitive data stored locally"}
              </p>
            </div>
            <div className="px-4 py-3">
              {!job.result.plaintext_withheld ? (
                <div>
                  <p className={labelClass}>Recovered plaintext</p>
                  <code className="mono block break-all rounded-lg border border-success/25 bg-surface px-3 py-2 text-base text-success">
                    {job.result.matched_plaintext}
                  </code>
                </div>
              ) : (
                <p className="text-xs text-warning">
                  Plaintext withheld from local history at your request.
                </p>
              )}
              <p className="mono mt-2 break-all text-xs text-text-muted">
                {job.result.target_hash}
              </p>
            </div>
          </div>
        )}
        {job.state === "paused" && !job.result && (
          <p className="mt-4 rounded-xl border border-warning/40 bg-warning/10 px-3 py-2 text-sm text-warning">
            Job paused — progress is checkpointed. Resume to continue from
            attempt {job.attempts.toLocaleString()}.
          </p>
        )}
        {job.result?.targets && (
          <div className="mt-4">
            <p className="mb-2 text-sm font-semibold text-text">
              Per-target results{" "}
              <span className="mono text-xs text-text-muted">
                batch {job.result.batch_id}
              </span>
            </p>
            {job.result.plaintext_withheld && (
              <p className="mb-2 text-xs text-warning">
                Plaintext withheld from local history at your request.
              </p>
            )}
            <div className="overflow-x-auto rounded-xl border border-border bg-surface-raised/25">
              <table className="w-full text-left text-sm">
                <thead>
                  <tr className="border-b border-border bg-surface-raised/60 text-[10px] font-bold section-label text-text-muted">
                    <th className="py-2 pr-4">Status</th>
                    <th className="py-2 pr-4">Algorithm</th>
                    <th className="py-2 pr-4">Hash</th>
                    <th className="py-2 pr-4 text-right">Matched at</th>
                    <th className="py-2">Plaintext</th>
                  </tr>
                </thead>
                <tbody className="mono text-xs">
                  {job.result.targets.map((t) => (
                    <tr
                      key={t.id}
                      className="border-b border-border/60 text-text-muted transition-colors last:border-b-0 hover:bg-surface-raised/50"
                    >
                      <td className="py-2 pr-4">
                        <span
                          className={
                            t.status === "match"
                              ? "text-success"
                              : "text-text-muted"
                          }
                        >
                          {STATUS_LABELS[t.status] || t.status}
                        </span>
                      </td>
                      <td className="py-2 pr-4">
                        {label(t.algorithm)}
                      </td>
                      <td className="py-2 pr-4 break-all">{t.hash.slice(0, 24)}…</td>
                      <td className="py-2 pr-4 text-right">
                        {t.match_at_attempt !== null
                          ? `#${t.match_at_attempt.toLocaleString()}`
                          : "—"}
                      </td>
                      <td className="py-2">
                        {t.plaintext_withheld && t.status === "match" ? (
                          "Withheld"
                        ) : t.matched_plaintext === null ? (
                          "—"
                        ) : (
                          <span className="text-success">{t.matched_plaintext}</span>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}
        {job.result && job.result.status !== "match" && !job.result.targets && (
          <p className="mt-4 text-sm text-text-muted">
            Terminal status recorded. No plaintext was recovered.
          </p>
        )}
        {job.error && (
          <p className="mt-4 rounded-xl border border-danger/40 bg-danger/10 px-3 py-2 text-sm text-danger">
            {job.error}
          </p>
        )}
      </div>
    </section>
  );
}

export default JobProgressCard;
