import { useEffect } from "react";
import { X } from "lucide-react";

// Changelog modal, styled after the CyberSec Arsenal modals. Content mirrors
// the repository root CHANGELOG.md in condensed form.

const CHANGELOG = [
  {
    version: "v2.0.0",
    date: "2026-11-06",
    title: "Feature Expansion",
    items: [
      "Salted fast-hash formats — md5/sha1/sha256/sha512 with pass-salt or salt-pass order (hashcat 10/20/110/120/1410/1420/1710/1720)",
      "Hashlist multi-target audits — one candidate stream vs many targets, per-target results, batch records",
      "Mutation rules — capitalize, upper, lower, leetspeak, digit/year suffixes, combined preset",
      "benchmark command — per-algorithm candidates/second on this machine",
      "Pause & resume for dashboard jobs with exact attempt accounting",
      "Dashboard export (CSV/JSON) and ETA display",
      "Plaintext withholding option and optional at-rest encryption (passphrase-based)",
      "New formats: RIPEMD-160, SHA-512/224, SHA-512/256, bcrypt, sha512crypt, phpass",
      "131 automated tests + GitHub Actions CI on Windows and Linux",
    ],
  },
  {
    version: "v1.1.0",
    date: "2026-11-05",
    title: "Format Expansion",
    items: [
      "SHA-1, SHA-224, SHA-384, SHA-512 via hashlib",
      "MD4 (raw UTF-8, hashcat 900) and LM (first DES block, hashcat 3000)",
      "32-hex shapes are now a three-way ambiguity: MD5 / NTLM / MD4",
      "Validated against hashcat's official example hashes",
    ],
  },
  {
    version: "v1.0.0",
    date: "2026-11-05",
    title: "Initial Release",
    items: [
      "Hash identification with honest ambiguity handling",
      "Dictionary and bounded brute-force auditing with a multiprocessing engine (1–8 workers)",
      "CLI (identify / audit / history / export / serve) and local web dashboard",
      "SQLite history with CSV/JSON export and sensitive-data warnings",
      "Clear-history confirmation, Auto-fit settings, backend-detection banner",
      "CyberSec Arsenal-styled UI: dark/light themes, particles, self-hosted fonts",
    ],
  },
];

export default function ChangelogModal({ isOpen, onClose }) {
  useEffect(() => {
    if (!isOpen) return;
    const onKey = (e) => {
      if (e.key === "Escape") onClose();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [isOpen, onClose]);

  if (!isOpen) return null;

  return (
    <div
      className="fixed inset-0 z-40 flex items-center justify-center bg-black/60 p-4 backdrop-blur-sm"
      role="dialog"
      aria-modal="true"
      aria-labelledby="changelog-title"
      onClick={(e) => {
        if (e.target === e.currentTarget) onClose();
      }}
    >
      <div className="animate-modal-enter card flex max-h-[80vh] w-full max-w-2xl flex-col">
        <div className="card-header flex items-center justify-between px-5 py-3">
          <h3 id="changelog-title" className="text-sm font-bold text-text">
            Changelog
          </h3>
          <button
            className="pill-cta"
            onClick={onClose}
            aria-label="Close changelog"
          >
            <X size={18} />
          </button>
        </div>
        <div className="overflow-y-auto px-5 py-4">
          {CHANGELOG.map((release) => (
            <div key={release.version} className="mb-6 last:mb-1">
              <div className="flex items-center gap-3">
                <span className="mono rounded-lg border border-accent/40 bg-accent/10 px-2 py-0.5 text-xs font-bold text-accent">
                  {release.version}
                </span>
                <span className="mono text-xs text-text-muted">{release.date}</span>
                <span className="text-sm font-semibold text-text">{release.title}</span>
              </div>
              <ul className="mt-2.5 flex flex-col gap-1.5 text-[13px] leading-relaxed text-text-muted">
                {release.items.map((item) => (
                  <li key={item} className="flex gap-2">
                    <ChevronDot />
                    <span>{item}</span>
                  </li>
                ))}
              </ul>
            </div>
          ))}
          <p className="border-t border-border pt-3 text-xs text-text-muted">
            Full details in the repository{" "}
            <span className="mono text-accent">CHANGELOG.md</span>.
          </p>
        </div>
      </div>
    </div>
  );
}

function ChevronDot() {
  return <span className="mt-1.5 h-1 w-1 shrink-0 rounded-full bg-accent" />;
}
