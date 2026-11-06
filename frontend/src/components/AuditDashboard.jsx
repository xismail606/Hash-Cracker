import { useEffect, useRef, useState } from "react";
import {
  Search,
  FileText,
  Zap,
  Play,
  Square,
  History,
  RefreshCw,
  Terminal,
  Trash2,
  AlertTriangle,
  Sparkles,
  KeyRound,
} from "lucide-react";

// Local dashboard for the offline hash-audit engine. Talks only to the
// loopback Flask API; state-changing requests carry the CSRF token issued by
// GET /api/session.
//
// Visual system adopted from the CyberSec Arsenal site: emerald on deep
// black with a glowing radial gradient, translucent rounded cards, glow
// accent buttons, Geist Sans/Mono, dark/light theme toggle.

const ALGORITHM_LABELS = {
  md5: "MD5",
  md5_pass_salt: "md5($pass.$salt)",
  md5_salt_pass: "md5($salt.$pass)",
  sha1_pass_salt: "sha1($pass.$salt)",
  sha1_salt_pass: "sha1($salt.$pass)",
  sha256_pass_salt: "sha256($pass.$salt)",
  sha256_salt_pass: "sha256($salt.$pass)",
  sha512_pass_salt: "sha512($pass.$salt)",
  sha512_salt_pass: "sha512($salt.$pass)",
  ripemd160: "RIPEMD-160",
  sha512_224: "SHA-512/224",
  sha512_256: "SHA-512/256",
  bcrypt: "bcrypt",
  sha512crypt: "sha512crypt",
  phpass: "phpass",
  sha256: "SHA-256",
  ntlm: "NTLM",
  sha1: "SHA-1",
  sha224: "SHA-224",
  sha384: "SHA-384",
  sha512: "SHA-512",
  md4: "MD4",
  lm: "LM",
};
const STATUS_LABELS = {
  match: "Match",
  no_match: "No match",
  budget_exhausted: "Budget exhausted",
  paused: "Paused",
  cancelled: "Cancelled",
  interrupted: "Interrupted",
  invalid_input: "Invalid input",
  storage_error: "Storage error",
};
const STATUS_TONE = {
  match: "text-success border-success/40 bg-success/10",
  no_match: "text-text-muted border-border bg-surface-raised",
  budget_exhausted: "text-warning border-warning/40 bg-warning/10",
  cancelled: "text-warning border-warning/40 bg-warning/10",
  interrupted: "text-danger border-danger/40 bg-danger/10",
  invalid_input: "text-danger border-danger/40 bg-danger/10",
  storage_error: "text-danger border-danger/40 bg-danger/10",
};
const SALTED_BY_LENGTH = {
  32: ["md5_pass_salt", "md5_salt_pass"],
  40: ["sha1_pass_salt", "sha1_salt_pass"],
  64: ["sha256_pass_salt", "sha256_salt_pass"],
  128: ["sha512_pass_salt", "sha512_salt_pass"],
};
const isSalted = (name) => name.endsWith("_pass_salt") || name.endsWith("_salt_pass");

const RULES_PRESETS = [
  { name: "none", label: "No rules (original words only)" },
  { name: "capitalize", label: "Capitalize first letter" },
  { name: "upper", label: "UPPERCASE" },
  { name: "lower", label: "lowercase" },
  { name: "leetspeak", label: "Leetspeak (a→4, e→3, i→1, o→0, s→5)" },
  { name: "append_digits_0_99", label: "Append digits 0–99" },
  { name: "append_years", label: "Append years 1990–2029" },
  { name: "all", label: "All of the above combined" },
];

const CHARSET_PRESETS = [
  { name: "lower", label: "lowercase a-z" },
  { name: "upper", label: "uppercase A-Z" },
  { name: "digits", label: "digits 0-9" },
  { name: "symbols", label: "symbols" },
];

const labelClass =
  "mb-1.5 block text-[10px] font-bold section-label text-text-muted";

async function apiFetch(path, options = {}) {
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

function CardHeader({ icon, title, right, id }) {
  return (
    <div className="card-header flex items-center justify-between px-5 py-3">
      <h2 id={id} className="flex items-center gap-2.5 text-sm font-bold text-text">
        <span className="flex h-7 w-7 items-center justify-center rounded-lg border border-accent/20 bg-accent/10 text-accent">
          {icon}
        </span>
        {title}
      </h2>
      {right}
    </div>
  );
}

export default function AuditDashboard() {
  // Identification
  const [hashInput, setHashInput] = useState("");
  const [identification, setIdentification] = useState(null);
  const [identifyError, setIdentifyError] = useState(null);
  const [algorithm, setAlgorithm] = useState("");

  // Audit settings
  const [mode, setMode] = useState("dictionary");
  const [wordlistFile, setWordlistFile] = useState(null);
  const [hashlistFile, setHashlistFile] = useState(null);
  const [rulesPreset, setRulesPreset] = useState("none");
  const [charsetPresets, setCharsetPresets] = useState(["lower"]);
  const [customCharset, setCustomCharset] = useState("");
  const [minLength, setMinLength] = useState(1);
  const [maxLength, setMaxLength] = useState(4);
  const [maxCandidates, setMaxCandidates] = useState(1000000);
  const [workers, setWorkers] = useState(4);
  const [acknowledged, setAcknowledged] = useState(false);
  const [salt, setSalt] = useState("");
  const [etaSeconds, setEtaSeconds] = useState(null);
  const [storePlaintext, setStorePlaintext] = useState(true);

  // Job state
  const [jobId, setJobId] = useState(null);
  const [job, setJob] = useState(null);
  const [starting, setStarting] = useState(false);
  const [error, setError] = useState(null);
  const [csrfToken, setCsrfToken] = useState("");
  const [serverMissing, setServerMissing] = useState(false);
  const pollRef = useRef(null);

  // History
  const [history, setHistory] = useState(null);
  const [historyNote, setHistoryNote] = useState("");
  const [confirmClear, setConfirmClear] = useState(false);
  const [clearing, setClearing] = useState(false);
  const [encryptedCount, setEncryptedCount] = useState(0);
  const [unlockPassphrase, setUnlockPassphrase] = useState("");
  const [unlocking, setUnlocking] = useState(false);

  // Brute-force auto-fit suggestion
  const [suggestion, setSuggestion] = useState(null);
  const [suggesting, setSuggesting] = useState(false);

  useEffect(() => {
    // The API exists only on the Flask server; detect a static-only serving
    // (astro preview, plain file hosting) and tell the operator what to run.
    fetch("/api/session", { credentials: "same-origin" })
      .then(async (response) => {
        if (!response.ok) throw new Error(`backend status ${response.status}`);
        const payload = await response.json();
        setCsrfToken(payload.csrf_token);
      })
      .catch(() => setServerMissing(true));
    refreshHistory();
    return () => clearInterval(pollRef.current);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  function refreshHistory() {
    apiFetch("/api/history")
      .then((payload) => {
        setHistory(payload.records);
        setHistoryNote(payload.sensitive_note || "");
        setEncryptedCount(payload.encrypted_count || 0);
      })
      .catch((err) => {
        if (history === null) setHistory([]);
        setError(err.message);
      });
  }

  async function unlockHistory() {
    if (!unlockPassphrase) {
      setError("Enter the history encryption passphrase to unlock.");
      return;
    }
    setUnlocking(true);
    try {
      await apiFetch("/api/history/unlock", {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-CSRF-Token": csrfToken },
        body: JSON.stringify({ passphrase: unlockPassphrase }),
      });
      setUnlockPassphrase("");
      refreshHistory();
    } catch (err) {
      setError(err.message);
    } finally {
      setUnlocking(false);
    }
  }

  async function identifyHash(value = hashInput) {
    setIdentification(null);
    setIdentifyError(null);
    if (!value.trim()) return;
    try {
      const payload = await apiFetch("/api/identify", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ hash: value }),
      });
      setIdentification(payload);
      setSalt("");
      setAlgorithm(
        payload.compatible_algorithms.length === 1 ? payload.compatible_algorithms[0] : ""
      );
    } catch (err) {
      setIdentification(null);
      setIdentifyError(err.message);
    }
  }

  function startPolling(id) {
    clearInterval(pollRef.current);
    let prev = null; // { attempts, ts }
    pollRef.current = setInterval(async () => {
      try {
        const payload = await apiFetch(`/api/audits/${id}`);
        setJob(payload);
        if (payload.budget && !payload.result && !payload.error) {
          const now = performance.now();
          if (prev && payload.attempts >= prev.attempts) {
            const rate = (payload.attempts - prev.attempts) / ((now - prev.ts) / 1000);
            const remaining = payload.budget - payload.attempts;
            setEtaSeconds(rate > 0 ? Math.round(remaining / rate) : null);
          }
          prev = { attempts: payload.attempts, ts: now };
        } else {
          setEtaSeconds(null);
        }
        if (payload.result || payload.error) {
          clearInterval(pollRef.current);
          setEtaSeconds(null);
          refreshHistory();
        }
      } catch (err) {
        clearInterval(pollRef.current);
        setError(err.message);
      }
    }, 500);
  }

  async function startAudit() {
    setError(null);
    setJob(null);
    setJobId(null);
    setStarting(true);
    try {
      const form = new FormData();
      form.append("mode", mode);
      form.append("hash", hashInput.trim());
      form.append("algorithm", algorithm);
      form.append("rules", mode === "dictionary" ? rulesPreset : "none");
      if (hashlistFile) {
        form.append("hashlist", hashlistFile);
      }
      form.append("workers", String(workers));
      if (isSalted(algorithm)) {
        if (!salt.trim())
          throw new Error(`Salted format ${ALGORITHM_LABELS[algorithm] || algorithm} requires a salt value.`);
        form.append("salt", salt.trim());
      }
      form.append("acknowledge_retention", "true");
      form.append("store_plaintext", storePlaintext ? "true" : "false");
      if (mode === "dictionary") {
        if (!wordlistFile)
          throw new Error("Select a UTF-8 wordlist file to upload (max 256 MiB).");
        form.append("wordlist", wordlistFile);
      } else {
        const presetText = charsetPresets.join(",");
        const charset = [presetText, customCharset].filter(Boolean).join(",");
        form.append("charset", charset);
        form.append("min_length", String(minLength));
        form.append("max_length", String(maxLength));
        form.append("max_candidates", String(maxCandidates));
      }
      const payload = await fetch("/api/audits", {
        method: "POST",
        credentials: "same-origin",
        headers: { "X-CSRF-Token": csrfToken },
        body: form,
      });
      const body = await payload.json().catch(() => ({}));
      if (!payload.ok)
        throw new Error(body.error || `Audit start failed (${payload.status})`);
      setJobId(body.job_id);
      startPolling(body.job_id);
    } catch (err) {
      setError(err.message);
    } finally {
      setStarting(false);
    }
  }

  async function pauseAudit() {
    if (!jobId) return;
    try {
      await apiFetch(`/api/audits/${jobId}/pause`, {
        method: "POST",
        headers: { "X-CSRF-Token": csrfToken },
      });
    } catch (err) {
      setError(err.message);
    }
  }

  async function resumeAudit() {
    if (!jobId) return;
    try {
      await apiFetch(`/api/audits/${jobId}/resume`, {
        method: "POST",
        headers: { "X-CSRF-Token": csrfToken },
      });
    } catch (err) {
      setError(err.message);
    }
  }

  async function cancelAudit() {
    if (!jobId) return;
    try {
      await apiFetch(`/api/audits/${jobId}/cancel`, {
        method: "POST",
        headers: { "X-CSRF-Token": csrfToken },
      });
    } catch (err) {
      setError(err.message);
    }
  }

  async function clearHistory() {
    setClearing(true);
    try {
      await apiFetch("/api/history/clear", {
        method: "POST",
        headers: { "X-CSRF-Token": csrfToken },
      });
      setConfirmClear(false);
      setHistory([]);
      setHistoryNote("");
      refreshHistory();
    } catch (err) {
      setError(err.message);
      setConfirmClear(false);
    } finally {
      setClearing(false);
    }
  }

  const ambiguous = identification?.ambiguous;
  const saltedOptions =
    identification?.valid
      ? SALTED_BY_LENGTH[identification.normalized.length] || []
      : [];
  const canAudit =
    acknowledged &&
    !starting &&
    !serverMissing &&
    (hashlistFile !== null ||
      (identification?.valid &&
        algorithm &&
        (!isSalted(algorithm) || salt.trim() !== ""))) &&
    (mode === "dictionary" ? wordlistFile !== null : true);
  const running = job && !job.result && !job.error;
  const budgetFraction =
    job && job.budget && job.budget > 0 ? Math.min(job.attempts / job.budget, 1) : null;

  // Identify the current hash and pre-fill brute-force settings that fit the
  // candidate budget: a default password alphabet and the largest length
  // range whose full search space stays inside the budget.
  async function suggestBruteForce() {
    setError(null);
    setSuggestion(null);
    if (!hashInput.trim()) {
      setError("Paste a target hash first, then click Auto-fit.");
      return;
    }
    setSuggesting(true);
    try {
      const payload = await apiFetch("/api/identify", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ hash: hashInput }),
      });
      setIdentification(payload);
      if (payload.compatible_algorithms.length === 1) {
        setAlgorithm(payload.compatible_algorithms[0]);
      }
      // For an ambiguous shape (MD5/NTLM) the algorithm stays unselected on
      // purpose: the tool never guesses through the overlap.

      // LM stores uppercase comparisons (hashcat's upper-case convention), so
      // an identified LM target auto-fits an upper-only alphabet instead.
      const isLm =
        payload.compatible_algorithms.length === 1 &&
        payload.compatible_algorithms[0] === "lm";
      const names = isLm ? ["upper"] : ["lower", "digits"];
      const alphabetSize = isLm ? 26 : 36; // |upper| vs |lower + digits|
      const alphabetLabel = isLm ? "upper" : "lower+digits";
      const budget = maxCandidates;
      let fitLength = 0;
      let covered = 0;
      for (let len = 1; len <= 12; len++) {
        const next = covered + alphabetSize ** len;
        if (next > budget) break;
        covered = next;
        fitLength = len;
      }
      if (fitLength === 0) {
        setSuggestion({
          ok: false,
          text: `Budget ${budget.toLocaleString()} is too small for even 1-character candidates over ${alphabetSize} characters. Raise the budget or clear some character sets.`,
        });
        return;
      }
      setCharsetPresets(names);
      setCustomCharset("");
      setMinLength(1);
      setMaxLength(fitLength);
      setSuggestion({
        ok: true,
        text: `Identified ${
          payload.compatible_algorithms.map((n) => ALGORITHM_LABELS[n]).join(", ")
        }${
          payload.ambiguous
            ? " — ambiguous shape, pick the algorithm below before starting"
            : " — selected"
        }; set charset ${alphabetLabel} (${alphabetSize} characters)${
          isLm ? " — LM compares uppercase only" : ""
        } and lengths 1–${fitLength}, covering a full space of ${covered.toLocaleString()} candidates within the ${budget.toLocaleString()} budget.`,
      });
    } catch (err) {
      setError(err.message);
    } finally {
      setSuggesting(false);
    }
  }

  return (
    <div className="space-y-8">
      {serverMissing && (
        <div
          role="alert"
          className="rounded-2xl border border-danger/40 bg-danger/10 px-4 py-3 text-sm leading-relaxed text-danger backdrop-blur-sm"
        >
          <p className="font-bold">Flask backend not detected.</p>
          <p className="mt-1 text-text">
            The dashboard API lives on the local Flask server only. Stop this
            server and run{" "}
            <code className="mono rounded border border-border bg-surface px-1">
              python -m password_audit serve
            </code>{" "}
            in the project root, then open the printed http://127.0.0.1 URL. (For
            frontend development, start the Flask server on port 8765 first so{" "}
            <code className="mono rounded border border-border bg-surface px-1">
              npm run dev
            </code>{" "}
            can proxy to it.)
          </p>
        </div>
      )}

      {/* Target hash */}
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
                onChange={(e) => setHashInput(e.target.value)}
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
                    .map((name) => ALGORITHM_LABELS[name])
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
                      onChange={() => {
                        setAlgorithm(name);
                        setSalt("");
                      }}
                    />
                    {ALGORITHM_LABELS[name]}
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
                    onChange={(e) => {
                      setAlgorithm(e.target.value);
                      setSalt("");
                    }}
                    disabled={running}
                  >
                    <option value="">None (unsalted shape formats only)</option>
                    {saltedOptions.map((name) => (
                      <option key={name} value={name}>
                        {ALGORITHM_LABELS[name]}
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
                        onChange={(e) => setSalt(e.target.value)}
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

      {/* Audit mode */}
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
              onChange={(e) => setHashlistFile(e.target.files?.[0] || null)}
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
                onClick={() => setMode(m)}
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
                onChange={(e) => setWordlistFile(e.target.files?.[0] || null)}
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
                  onChange={(e) => setRulesPreset(e.target.value)}
                  disabled={running}
                >
                  {RULES_PRESETS.map((preset) => (
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
                  {CHARSET_PRESETS.map((preset) => (
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
                          setCharsetPresets((current) =>
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
                  onChange={(e) => setCustomCharset(e.target.value)}
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
                    onChange={(e) => setMinLength(Number(e.target.value))}
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
                    onChange={(e) => setMaxLength(Number(e.target.value))}
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
                    onChange={(e) => setMaxCandidates(Number(e.target.value))}
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
              onChange={(e) => setWorkers(Number(e.target.value))}
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

      {/* Acknowledgement + run */}
      <section className="card" aria-labelledby="step-run">
        <CardHeader id="step-run" icon={<Play size={15} />} title="Run" />
        <div className="px-5 py-4">
          <label className="flex cursor-pointer items-start gap-3 text-sm leading-relaxed text-text-muted">
            <input
              type="checkbox"
              className="mt-1 accent-accent"
              checked={acknowledged}
              onChange={(e) => setAcknowledged(e.target.checked)}
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
              onChange={(e) => setStorePlaintext(e.target.checked)}
              disabled={running}
            />
            <span>
              Store the recovered plaintext in local history on a match
              (uncheck to record the match without it).
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

      {/* Progress / result */}
      {job && (
        <section className="card" aria-labelledby="step-progress">
          <CardHeader
            id="step-progress"
            icon={<Zap size={15} />}
            title="Progress and result"
            right={
              <span className="mono text-xs text-text-muted">{job.job_id.slice(0, 8)}</span>
            }
          />
          <div className="px-5 py-4">
            <dl className="grid grid-cols-2 gap-x-6 gap-y-4 sm:grid-cols-4">
              <div>
                <dt className={labelClass}>State</dt>
                <dd className="mt-1">
                  {job.result ? (
                    <span
                      className={`pill mono rounded-lg ${STATUS_TONE[job.result.status] || "text-text-muted border-border bg-surface-raised"}`}
                    >
                      {STATUS_LABELS[job.result.status] || job.result.status}
                    </span>
                  ) : (
                    <span className="mono text-sm text-text">{job.state}</span>
                  )}
                </dd>
              </div>
              <div>
                <dt className={labelClass}>Attempts</dt>
                <dd className="mono mt-1 text-sm font-semibold text-text">
                  {job.attempts.toLocaleString()}
                </dd>
              </div>
              <div>
                <dt className={labelClass}>Elapsed</dt>
                <dd className="mono mt-1 text-sm font-semibold text-text">
                  {(job.elapsed_ms / 1000).toFixed(1)}s
                </dd>
              </div>
              <div>
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
                    className="h-full rounded-full bg-accent transition-[width] duration-500"
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
              <div className="mt-4 rounded-2xl border border-success/30 bg-success/10 px-4 py-3">
                <p className="flex items-center gap-2 text-sm font-bold text-success">
                  <span className="h-1.5 w-1.5 animate-pulse rounded-full bg-success"></span>
                  {job.result.plaintext_withheld
                    ? "Match — plaintext withheld"
                    : "Match — sensitive data stored locally"}
                </p>
                {!job.result.plaintext_withheld && (
                  <p className="mono mt-2 break-all text-sm text-text">
                    Plaintext: {job.result.matched_plaintext}
                  </p>
                )}
                <p className="mono mt-1 break-all text-sm text-text-muted">
                  {job.result.target_hash}
                </p>
                {job.result.plaintext_withheld && (
                  <p className="mt-2 text-xs text-warning">
                    Plaintext withheld from local history at your request.
                  </p>
                )}
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
                <div className="overflow-x-auto">
                  <table className="w-full text-left text-sm">
                    <thead>
                      <tr className="border-b border-border text-[10px] font-bold section-label text-text-muted">
                        <th className="py-2 pr-4">Status</th>
                        <th className="py-2 pr-4">Algorithm</th>
                        <th className="py-2 pr-4">Hash</th>
                        <th className="py-2 pr-4 text-right">Matched at</th>
                        <th className="py-2">Plaintext</th>
                      </tr>
                    </thead>
                    <tbody className="mono text-xs">
                      {job.result.targets.map((t) => (
                        <tr key={t.id} className="border-b border-border/60 text-text-muted">
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
                            {ALGORITHM_LABELS[t.algorithm] || t.algorithm}
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
      )}

      {/* History */}
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
                  onClick={() => setConfirmClear(true)}
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
                    onChange={(e) => setUnlockPassphrase(e.target.value)}
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
                  <tr className="border-b border-border text-[10px] font-bold section-label text-text-muted">
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
                    <tr key={record.run_id} className="border-b border-border/60 text-text-muted">
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
                        {ALGORITHM_LABELS[record.algorithm] || record.algorithm}
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

      {/* Clear-history confirmation modal */}
      {confirmClear && (
        <div
          className="fixed inset-0 z-40 flex items-center justify-center bg-black/60 p-4 backdrop-blur-sm"
          role="dialog"
          aria-modal="true"
          aria-labelledby="clear-history-title"
          onClick={(e) => {
            if (e.target === e.currentTarget && !clearing) setConfirmClear(false);
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
              <span className="mono font-semibold text-text">
                {history?.length ?? 0}
              </span>{" "}
              local audit records, including every saved plaintext/hash pair and
              its run metadata. This cannot be undone.
            </p>
            <div className="mt-5 flex justify-end gap-3">
              <button
                className="btn-secondary px-4 py-2.5 text-sm"
                onClick={() => setConfirmClear(false)}
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
      )}
    </div>
  );
}
