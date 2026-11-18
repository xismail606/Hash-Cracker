// Target-hash identification card: input, Identify button, compatible
// algorithm radio chips, and the salted-format override + salt value field.

import { Search, Terminal } from "lucide-react";

import CardHeader from "./Card.jsx";
import { isSalted, labelClass } from "./shared.js";

export function IdentifyCard({
  hashInput,
  onHashInput,
  identifyHash,
  identifyError,
  identification,
  label,
  algorithm,
  onAlgorithmChange,
  salt,
  onSaltChange,
  saltedOptions,
  running,
}) {
  const ambiguous = identification?.ambiguous;

  return (
    <section className="card" aria-labelledby="step-hash">
      <CardHeader id="step-hash" icon={<Search size={15} />} title="Target hash" />
      <div className="px-5 py-4">
        <div className="flex flex-col gap-2 sm:flex-row">
          <div className="relative flex-1">
            <Terminal
              size={15}
              className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-accent"
            />
            <input
              className="input mono py-2.5 pl-9 pr-3 text-base"
              value={hashInput}
              placeholder="32-character (MD5/NTLM) or 64-character (SHA-256) hex digest"
              spellCheck={false}
              onChange={(e) => onHashInput(e.target.value)}
            />
          </div>
          <button className="btn-secondary px-5 py-2.5 text-sm" onClick={() => identifyHash()}>
            Identify format
          </button>
        </div>
        {identifyError && (
          <p className="mt-3 rounded-xl border border-danger/40 bg-danger/10 px-3 py-2 text-sm text-danger">
            {identifyError}
          </p>
        )}
        {identification?.valid && (
          <div className="mt-4">
            <p className="text-sm text-text-muted">
              Shape:{" "}
              <span className="mono font-semibold text-text">
                {identification.normalized.length}
              </span>{" "}
              hex characters · Compatible formats:{" "}
              <span className="font-semibold text-text">
                {identification.compatible_algorithms
                  .map((name) => label(name))
                  .join(", ")}
              </span>
              {ambiguous && (
                <span className="text-warning"> — ambiguous shape; choose one explicitly.</span>
              )}
            </p>
            <div className="mt-3 flex flex-wrap gap-2" role="radiogroup" aria-label="Algorithm">
              {identification.compatible_algorithms.map((name) => (
                <label
                  key={name}
                  className={`mono cursor-pointer rounded-xl border px-4 py-2 text-sm transition-all duration-200 ${
                    algorithm === name
                      ? "border-accent/50 bg-accent/10 text-accent"
                      : "border-border bg-surface text-text-muted hover:border-accent/30 hover:text-text"
                  }`}
                >
                  <input
                    type="radio"
                    name="algorithm"
                    className="sr-only"
                    checked={algorithm === name}
                    onChange={() => onAlgorithmChange(name)}
                  />
                  {label(name)}
                </label>
              ))}
            </div>
            {saltedOptions.length > 0 && (
              <div className="mt-4">
                <label className={labelClass} htmlFor="salted-format">
                  Salted format (advanced — hashcat modes 10/20/110/120/1410/1420/1710/1720)
                </label>
                <select
                  id="salted-format"
                  className="input mono px-3 py-2.5 text-sm"
                  value={saltedOptions.includes(algorithm) ? algorithm : ""}
                  onChange={(e) => onAlgorithmChange(e.target.value)}
                  disabled={running}
                >
                  <option value="">None (unsalted shape formats only)</option>
                  {saltedOptions.map((name) => (
                    <option key={name} value={name}>
                      {label(name)}
                    </option>
                  ))}
                </select>
                {algorithm && isSalted(algorithm) && (
                  <div className="mt-3">
                    <label className={labelClass} htmlFor="salt-value">
                      Salt value (required — the known salt stored with this hash)
                    </label>
                    <input
                      id="salt-value"
                      className="input mono px-3 py-2.5 text-sm"
                      value={salt}
                      spellCheck={false}
                      placeholder="e.g. 343141"
                      onChange={(e) => onSaltChange(e.target.value)}
                      disabled={running}
                    />
                  </div>
                )}
              </div>
            )}
          </div>
        )}
      </div>
    </section>
  );
}

export default IdentifyCard;
