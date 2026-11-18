// Audit-mode card: optional hashlist, dictionary/brute-force tabs, the
// per-mode settings (wordlist + rules vs charset/length/budget), and workers.

import { FileText, Sparkles, Zap } from "lucide-react";

import CardHeader from "./Card.jsx";
import { labelClass } from "./shared.js";

export function AuditModeCard({
  mode,
  onModeChange,
  hashlistFile,
  onHashlistChange,
  wordlistFile,
  onWordlistChange,
  rulesPreset,
  onRulesChange,
  charsetPresets,
  onCharsetPresetsChange,
  customCharset,
  onCustomCharsetChange,
  minLength,
  onMinLengthChange,
  maxLength,
  onMaxLengthChange,
  maxCandidates,
  onMaxCandidatesChange,
  workers,
  onWorkersChange,
  formats,
  suggestion,
  suggestBruteForce,
  suggesting,
  running,
}) {
  return (
    <section className="card" aria-labelledby="step-mode">
      <CardHeader
        id="step-mode"
        icon={mode === "dictionary" ? <FileText size={15} /> : <Zap size={15} />}
        title="Audit mode"
        right={
          mode === "brute-force" ? (
            <button
              type="button"
              className="btn-secondary flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-xs"
              onClick={suggestBruteForce}
              disabled={suggesting || running}
              title="Identify the target hash and fill brute-force settings that fit the budget"
            >
              <Sparkles size={12} className="text-accent" />
              {suggesting ? "Fitting…" : "Auto-fit"}
            </button>
          ) : undefined
        }
      />
      <div className="px-5 py-4">
        <div className="mb-5">
          <label className={labelClass} htmlFor="hashlist">
            Hashlist (optional — one target per line, e.g. md5:8743b5…; replaces the single hash)
          </label>
          <label
            htmlFor="hashlist"
            className="input mono flex cursor-pointer items-center justify-between px-3 py-2.5 text-sm"
          >
            <span className="truncate text-text">
              {hashlistFile
                ? `${hashlistFile.name} (${hashlistFile.size} bytes)`
                : "No hashlist — audit the single hash above"}
            </span>
            <span className="rounded-lg border border-border bg-surface-raised px-2.5 py-1 text-xs text-text-muted">
              Choose file
            </span>
          </label>
          <input
            id="hashlist"
            type="file"
            accept=".txt,.lst,.dic"
            className="sr-only"
            onChange={(e) => onHashlistChange(e.target.files?.[0] || null)}
            disabled={running}
          />
        </div>
        <div className="mb-5 grid grid-cols-2 gap-2">
          {[
            ["dictionary", "Dictionary", <FileText size={14} key="d" />],
            ["brute-force", "Brute force", <Zap size={14} key="b" />],
          ].map(([m, labelText, icon]) => (
            <button
              key={m}
              type="button"
              role="tab"
              aria-selected={mode === m}
              onClick={() => onModeChange(m)}
              disabled={running}
              className={`flex items-center justify-center gap-2 rounded-xl border px-4 py-2.5 text-sm font-bold transition-all duration-200 disabled:cursor-not-allowed disabled:opacity-40 ${
                mode === m
                  ? "border-accent/50 bg-accent/10 text-accent"
                  : "border-border bg-surface text-text-muted hover:border-accent/30 hover:text-text"
              }`}
            >
              {icon}
              {labelText}
            </button>
          ))}
        </div>
        {mode === "dictionary" ? (
          <div>
            <label className={labelClass} htmlFor="wordlist">
              Wordlist (UTF-8, up to 256 MiB)
            </label>
            <label
              htmlFor="wordlist"
              className="input mono flex cursor-pointer items-center justify-between px-3 py-2.5 text-sm hover:cursor-pointer"
            >
              <span className="truncate text-text">
                {wordlistFile ? wordlistFile.name : "No file selected"}
              </span>
              <span className="rounded-lg border border-border bg-surface-raised px-2.5 py-1 text-xs text-text-muted">
                Choose file
              </span>
            </label>
            <input
              id="wordlist"
              type="file"
              accept=".txt,.dic,.lst"
              className="sr-only"
              onChange={(e) => onWordlistChange(e.target.files?.[0] || null)}
              disabled={running}
            />
            <div className="mt-4 max-w-md">
              <label className={labelClass} htmlFor="rules-preset">
                Mutation rules (dictionary only)
              </label>
              <select
                id="rules-preset"
                className="input px-3 py-2.5 text-sm"
                value={rulesPreset}
                onChange={(e) => onRulesChange(e.target.value)}
                disabled={running}
              >
                {(formats?.rules_presets ?? []).map((preset) => (
                  <option key={preset.name} value={preset.name}>
                    {preset.label}
                  </option>
                ))}
              </select>
            </div>
          </div>
        ) : (
          <div className="space-y-5">
            {suggestion && (
              <p
                className={`rounded-xl border px-3 py-2 text-sm leading-relaxed ${
                  suggestion.ok
                    ? "border-accent/30 bg-accent/10 text-text"
                    : "border-danger/40 bg-danger/10 text-danger"
                }`}
                role="status"
              >
                <Sparkles size={12} className="mr-1.5 inline text-accent" />
                {suggestion.text}
              </p>
            )}
            <div>
              <span className={labelClass}>Character sets</span>
              <div className="flex flex-wrap gap-x-6 gap-y-2">
                {(formats?.charset_presets ?? []).map((preset) => (
                  <label
                    key={preset.name}
                    className="flex cursor-pointer items-center gap-2 text-sm"
                  >
                    <input
                      type="checkbox"
                      className="accent-accent"
                      checked={charsetPresets.includes(preset.name)}
                      disabled={running}
                      onChange={(e) => {
                        onCharsetPresetsChange((current) =>
                          e.target.checked
                            ? [...current, preset.name]
                            : current.filter((name) => name !== preset.name)
                        );
                      }}
                    />
                    <span className="mono text-xs text-text-muted">{preset.label}</span>
                  </label>
                ))}
              </div>
            </div>
            <div>
              <label className={labelClass} htmlFor="custom-charset">
                Extra custom characters (optional)
              </label>
              <input
                id="custom-charset"
                className="input mono px-3 py-2.5 text-sm"
                value={customCharset}
                placeholder="e.g. xY3 or !@#"
                onChange={(e) => onCustomCharsetChange(e.target.value)}
                disabled={running}
              />
            </div>
            <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
              <div>
                <label className={labelClass} htmlFor="min-length">
                  Min length
                </label>
                <input
                  id="min-length"
                  type="number"
                  min="1"
                  className="input mono px-3 py-2.5 text-sm"
                  value={minLength}
                  onChange={(e) => onMinLengthChange(Number(e.target.value))}
                  disabled={running}
                />
              </div>
              <div>
                <label className={labelClass} htmlFor="max-length">
                  Max length
                </label>
                <input
                  id="max-length"
                  type="number"
                  min="1"
                  className="input mono px-3 py-2.5 text-sm"
                  value={maxLength}
                  onChange={(e) => onMaxLengthChange(Number(e.target.value))}
                  disabled={running}
                />
              </div>
              <div>
                <label className={labelClass} htmlFor="max-candidates">
                  Candidate budget
                </label>
                <input
                  id="max-candidates"
                  type="number"
                  min="1"
                  max="10000000"
                  step="1000"
                  className="input mono px-3 py-2.5 text-sm"
                  value={maxCandidates}
                  onChange={(e) => onMaxCandidatesChange(Number(e.target.value))}
                  disabled={running}
                />
              </div>
            </div>
            <p className="text-xs text-text-muted">
              Default budget 1,000,000 candidates · hard maximum 10,000,000 per run.
            </p>
          </div>
        )}
        <div className="mt-5 max-w-xs">
          <label className={labelClass} htmlFor="workers">
            Workers (multiprocessing, 1–8)
          </label>
          <select
            id="workers"
            className="input px-3 py-2.5 text-sm"
            value={workers}
            onChange={(e) => onWorkersChange(Number(e.target.value))}
            disabled={running}
          >
            {[1, 2, 3, 4, 5, 6, 7, 8].map((n) => (
              <option key={n} value={n}>
                {n} worker{n > 1 ? "s" : ""}
              </option>
            ))}
          </select>
        </div>
      </div>
    </section>
  );
}

export default AuditModeCard;
