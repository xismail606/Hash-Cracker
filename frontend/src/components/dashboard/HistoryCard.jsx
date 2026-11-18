// Audit-history card: export/refresh/clear actions, encrypted-history unlock,
// and the records table.

import { History, KeyRound, RefreshCw, Trash2 } from "lucide-react";

import CardHeader from "./Card.jsx";
import { STATUS_LABELS } from "./shared.js";

export function HistoryCard({
  history,
  historyNote,
  encryptedCount,
  unlockPassphrase,
  onUnlockPassphraseChange,
  unlockHistory,
  unlocking,
  refreshHistory,
  onRequestClear,
  running,
  clearing,
  serverMissing,
  label,
}) {
  return (
    <section className="card" aria-labelledby="step-history">
      <CardHeader
        id="step-history"
        icon={<History size={15} />}
        title="Audit history"
        right={
          <div className="flex items-center gap-2">
            <a
              href="/api/export?format=csv"
              className="btn-secondary flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-xs"
              download
            >
              CSV
            </a>
            <a
              href="/api/export?format=json"
              className="btn-secondary flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-xs"
              download
            >
              JSON
            </a>
            <button
              className="btn-secondary flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-xs"
              onClick={refreshHistory}
            >
              <RefreshCw size={12} />
              Refresh
            </button>
            {history !== null && history.length > 0 && (
              <button
                className="btn-secondary flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-xs !text-danger hover:!border-danger/50 hover:!text-danger"
                onClick={onRequestClear}
                disabled={running || clearing}
                aria-label="Clear all audit history"
              >
                <Trash2 size={12} />
                Clear all
              </button>
            )}
          </div>
        }
      />
      <div className="px-5 py-4">
        {historyNote && <p className="mb-3 text-xs text-text-muted">{historyNote}</p>}
        {encryptedCount > 0 && (
          <div className="mb-4 rounded-xl border border-accent/30 bg-accent/5 px-4 py-3">
            <p className="text-sm font-semibold text-text">
              {encryptedCount} encrypted plaintext{encryptedCount > 1 ? "s" : ""} in history
            </p>
            <p className="mt-1 text-xs text-text-muted">
              Enter the passphrase used when the run was encrypted (CLI{" "}
              <code className="mono rounded border border-border bg-surface px-1">--encrypt</code>)
              to display the stored values. Losing the passphrase makes them unrecoverable.
            </p>
            <div className="mt-2.5 flex flex-col gap-2 sm:flex-row">
              <div className="relative flex-1">
                <KeyRound
                  size={14}
                  className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-accent"
                />
                <input
                  type="password"
                  className="input mono py-2 pl-9 pr-3 text-sm"
                  value={unlockPassphrase}
                  placeholder="History encryption passphrase"
                  autoComplete="off"
                  onChange={(e) => onUnlockPassphraseChange(e.target.value)}
                  onKeyDown={(e) => {
                    if (e.key === "Enter" && !unlocking) unlockHistory();
                  }}
                />
              </div>
              <button
                className="btn-secondary px-4 py-2 text-sm"
                onClick={unlockHistory}
                disabled={unlocking || !unlockPassphrase}
              >
                {unlocking ? "Unlocking…" : "Unlock"}
              </button>
            </div>
          </div>
        )}
        {history === null ? (
          <p className="text-sm text-text-muted">Loading…</p>
        ) : history.length === 0 ? (
          <p className="text-sm text-text-muted">
            {serverMissing
              ? "History unavailable — this page is not served by the Flask backend."
              : "No local audit records yet."}
          </p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead>
                <tr className="border-b border-border bg-surface-raised/60 text-[10px] font-bold section-label text-text-muted">
                  <th className="py-2 pr-4">#</th>
                  <th className="py-2 pr-4">Started (UTC)</th>
                  <th className="py-2 pr-4">Status</th>
                  <th className="py-2 pr-4">Algorithm</th>
                  <th className="py-2 pr-4">Mode</th>
                  <th className="py-2 pr-4 text-right">Attempts</th>
                  <th className="py-2 pr-4 text-right">Elapsed</th>
                  <th className="py-2 pr-4">Workers</th>
                  <th className="py-2">Plaintext</th>
                </tr>
              </thead>
              <tbody className="mono text-xs">
                {history.map((record) => (
                  <tr
                    key={record.run_id}
                    className="border-b border-border/60 text-text-muted transition-colors last:border-b-0 hover:bg-surface-raised/50"
                  >
                    <td className="py-2 pr-4 font-semibold text-text">{record.run_id}</td>
                    <td className="py-2 pr-4">{record.started_at}</td>
                    <td className="py-2 pr-4">
                      <span
                        className={
                          record.status === "match"
                            ? "text-success"
                            : record.status === "no_match"
                              ? ""
                              : "text-warning"
                        }
                      >
                        {STATUS_LABELS[record.status] || record.status}
                      </span>
                    </td>
                    <td className="py-2 pr-4">
                      {label(record.algorithm)}
                    </td>
                    <td className="py-2 pr-4">{record.mode}</td>
                    <td className="py-2 pr-4 text-right text-text">
                      {record.attempts.toLocaleString()}
                    </td>
                    <td className="py-2 pr-4 text-right">{(record.elapsed_ms / 1000).toFixed(1)}s</td>
                    <td className="py-2 pr-4">{record.worker_count}</td>
                    <td className="py-2">
                      {record.plaintext_withheld && record.status === "match" ? (
                        <span className="text-warning">Withheld</span>
                      ) : record.matched_plaintext === null ? (
                        "—"
                      ) : record.matched_plaintext === "<encrypted>" ? (
                        <span className="text-text-muted">{record.matched_plaintext}</span>
                      ) : (
                        <span className="text-success">{record.matched_plaintext}</span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </section>
  );
}

export default HistoryCard;
