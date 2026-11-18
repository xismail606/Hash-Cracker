import { useCallback, useEffect, useRef, useState } from "react";

import AuditModeCard from "./dashboard/AuditModeCard.jsx";
import ClearHistoryModal from "./dashboard/ClearHistoryModal.jsx";
import HistoryCard from "./dashboard/HistoryCard.jsx";
import IdentifyCard from "./dashboard/IdentifyCard.jsx";
import JobProgressCard from "./dashboard/JobProgressCard.jsx";
import RunCard from "./dashboard/RunCard.jsx";
import { apiFetch, isSalted } from "./dashboard/shared.js";

// Local dashboard for the offline hash-audit engine. Talks only to the
// loopback Flask API; state-changing requests carry the CSRF token issued by
// GET /api/session.
//
// This component is the orchestrator: it owns all dashboard state and the
// API handlers, while the dashboard/* cards are presentational sections
// that receive their data and callbacks as props.
//
// Visual system adopted from the Hash Cracker webpage landing site: soft
// blue on blue-tinted near black with a glowing radial gradient, translucent
// rounded cards, glow accent buttons, Geist Sans/Mono, dark/light theme toggle.

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
  const [storePlaintext, setStorePlaintext] = useState(false);

  // Job state
  const [jobId, setJobId] = useState(null);
  const [job, setJob] = useState(null);
  const [starting, setStarting] = useState(false);
  const [error, setError] = useState(null);
  const [csrfToken, setCsrfToken] = useState("");
  const [serverMissing, setServerMissing] = useState(false);
  // Supported-format registries fetched from GET /api/formats (the Python
  // registries are the single source of truth for labels and limits).
  const [formats, setFormats] = useState(null);
  const pollRef = useRef(null);
  const progressRef = useRef(null);

  // Display label for an algorithm name from the server registry; unknown
  // names fall back to the raw identifier.
  const label = useCallback(
    (name) => formats?.labels?.[name] || name,
    [formats],
  );

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
    fetch("/api/formats", { credentials: "same-origin" })
      .then(async (response) => {
        if (!response.ok) throw new Error(`formats status ${response.status}`);
        setFormats(await response.json());
      })
      .catch(() => {
        // The session fetch reports a missing backend; leave formats unset.
      });
    refreshHistory();
    return () => clearInterval(pollRef.current);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Bring the progress card into view once a run reaches a terminal state —
  // the recovered plaintext is the payoff of the run, so surface it.
  useEffect(() => {
    if (!job?.result && !job?.error) return;
    const prefersReduced = window.matchMedia(
      "(prefers-reduced-motion: reduce)"
    ).matches;
    progressRef.current?.scrollIntoView({
      behavior: prefersReduced ? "auto" : "smooth",
      block: "start",
    });
    // Polling stops on a terminal state, so this fires once per run.
  }, [job?.result, job?.error]);

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
          throw new Error(`Salted format ${label(algorithm)} requires a salt value.`);
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

  const saltedOptions =
    identification?.valid
      ? formats?.salted_by_length?.[identification.normalized.length] || []
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
  const resultStatus = job?.result?.status;
  const terminalCardClass = job?.error
    ? "card-result-error"
    : resultStatus === "match"
      ? "card-result-match"
      : resultStatus
        ? "card-result-no-match"
        : "";

  // Identify the hash and fill a complete, runnable brute-force range within
  // the engine's hard candidate limit.
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
      const budget = formats?.hard_max_candidates;
      if (!budget) {
        setSuggestion({
          ok: false,
          text: "The format registry is not loaded yet; try Auto-fit again.",
        });
        return;
      }
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
      setMaxCandidates(covered);
      setSuggestion({
        ok: true,
        text: `Identified ${
          payload.compatible_algorithms.map((n) => label(n)).join(", ")
        }${
          payload.ambiguous
            ? " — ambiguous shape, pick the algorithm below before starting"
            : " — selected"
        }; applied charset ${alphabetLabel} (${alphabetSize} characters)${
          isLm ? " — LM compares uppercase only" : ""
        } and updated the length and candidate-budget fields to 1–${fitLength} and ${covered.toLocaleString()}, respectively, so the full configured search space can run.`,
      });
    } catch (err) {
      setError(err.message);
    } finally {
      setSuggesting(false);
    }
  }

  // Selecting an algorithm always resets the salt field.
  function chooseAlgorithm(name) {
    setAlgorithm(name);
    setSalt("");
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
              python -m hash_cracker serve
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

      <IdentifyCard
        hashInput={hashInput}
        onHashInput={setHashInput}
        identifyHash={identifyHash}
        identifyError={identifyError}
        identification={identification}
        label={label}
        algorithm={algorithm}
        onAlgorithmChange={chooseAlgorithm}
        salt={salt}
        onSaltChange={setSalt}
        saltedOptions={saltedOptions}
        running={running}
      />

      <AuditModeCard
        mode={mode}
        onModeChange={setMode}
        hashlistFile={hashlistFile}
        onHashlistChange={setHashlistFile}
        wordlistFile={wordlistFile}
        onWordlistChange={setWordlistFile}
        rulesPreset={rulesPreset}
        onRulesChange={setRulesPreset}
        charsetPresets={charsetPresets}
        onCharsetPresetsChange={setCharsetPresets}
        customCharset={customCharset}
        onCustomCharsetChange={setCustomCharset}
        minLength={minLength}
        onMinLengthChange={setMinLength}
        maxLength={maxLength}
        onMaxLengthChange={setMaxLength}
        maxCandidates={maxCandidates}
        onMaxCandidatesChange={setMaxCandidates}
        workers={workers}
        onWorkersChange={setWorkers}
        formats={formats}
        suggestion={suggestion}
        suggestBruteForce={suggestBruteForce}
        suggesting={suggesting}
        running={running}
      />

      <RunCard
        acknowledged={acknowledged}
        onAcknowledgedChange={setAcknowledged}
        storePlaintext={storePlaintext}
        onStorePlaintextChange={setStorePlaintext}
        startAudit={startAudit}
        starting={starting}
        canAudit={canAudit}
        running={running}
        job={job}
        pauseAudit={pauseAudit}
        resumeAudit={resumeAudit}
        cancelAudit={cancelAudit}
        error={error}
      />

      {job && (
        <JobProgressCard
          job={job}
          running={running}
          etaSeconds={etaSeconds}
          budgetFraction={budgetFraction}
          terminalCardClass={terminalCardClass}
          progressRef={progressRef}
          label={label}
        />
      )}

      <HistoryCard
        history={history}
        historyNote={historyNote}
        encryptedCount={encryptedCount}
        unlockPassphrase={unlockPassphrase}
        onUnlockPassphraseChange={setUnlockPassphrase}
        unlockHistory={unlockHistory}
        unlocking={unlocking}
        refreshHistory={refreshHistory}
        onRequestClear={() => setConfirmClear(true)}
        running={running}
        clearing={clearing}
        serverMissing={serverMissing}
        label={label}
      />

      <ClearHistoryModal
        confirmClear={confirmClear}
        onClose={() => setConfirmClear(false)}
        clearing={clearing}
        clearHistory={clearHistory}
        recordCount={history?.length ?? 0}
      />
    </div>
  );
}
