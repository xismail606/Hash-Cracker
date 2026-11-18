// Clear-history confirmation modal.

import { AlertTriangle, Trash2 } from "lucide-react";

export function ClearHistoryModal({
  confirmClear,
  onClose,
  clearing,
  clearHistory,
  recordCount,
}) {
  if (!confirmClear) return null;
  return (
    <div
      className="fixed inset-0 z-40 flex items-center justify-center bg-black/60 p-4 backdrop-blur-sm"
      role="dialog"
      aria-modal="true"
      aria-labelledby="clear-history-title"
      onClick={(e) => {
        if (e.target === e.currentTarget && !clearing) onClose();
      }}
    >
      <div className="animate-modal-enter card w-full max-w-md px-5 py-5">
        <div className="flex items-center gap-3">
          <span className="flex h-9 w-9 items-center justify-center rounded-xl border border-danger/30 bg-danger/10 text-danger">
            <AlertTriangle size={18} />
          </span>
          <h3 id="clear-history-title" className="text-sm font-bold text-text">
            Clear all audit history?
          </h3>
        </div>
        <p className="mt-3 text-sm leading-relaxed text-text-muted">
          This permanently deletes all{" "}
          <span className="mono font-semibold text-text">{recordCount}</span>{" "}
          local audit records, including every saved plaintext/hash pair and
          its run metadata. This cannot be undone.
        </p>
        <div className="mt-5 flex justify-end gap-3">
          <button
            className="btn-secondary px-4 py-2.5 text-sm"
            onClick={onClose}
            disabled={clearing}
          >
            Cancel
          </button>
          <button
            className="btn-danger flex items-center gap-2 px-4 py-2.5 text-sm"
            onClick={clearHistory}
            disabled={clearing}
          >
            <Trash2 size={14} />
            {clearing ? "Deleting…" : "Delete everything"}
          </button>
        </div>
      </div>
    </div>
  );
}

export default ClearHistoryModal;
