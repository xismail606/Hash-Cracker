import { ChevronRight, GitBranch, History, Terminal, Lock, Wifi, WifiOff } from "lucide-react";

// Footer adapted from the CyberSec Arsenal Footer: brand column, in-page
// quick links, safety notes, and a pulsing-dot bottom bar.
// Quick links point at the dashboard page's step anchors from every page.
const quickLinks = [
  { label: "Target hash", href: "/#step-hash" },
  { label: "Audit mode", href: "/#step-mode" },
  { label: "Run", href: "/#step-run" },
  { label: "Audit history", href: "/#step-history" },
];

const safetyNotes = [
  { Icon: Lock, label: "Loopback only — 127.0.0.1 binding" },
  { Icon: WifiOff, label: "No remote targets or logins" },
  { Icon: Wifi, label: "Zero external data transmission" },
];

export default function Footer() {
  return (
    <footer className="relative mt-14 w-full overflow-hidden border-t border-border py-9">
      <div className="mx-auto max-w-6xl px-4 sm:px-6">
        <div className="grid grid-cols-1 gap-6 border-b border-border pb-7 sm:gap-7 md:grid-cols-4 md:gap-10">
          {/* Column 1: Brand */}
          <div className="col-span-1 flex flex-col gap-3 md:col-span-2">
            <a
              href="/"
              aria-label="Hash Cracker home"
              className="group flex items-center gap-3 self-start"
            >
              <span className="flex h-10 w-10 items-center justify-center rounded-xl border border-accent/30 bg-accent/10 text-accent transition-transform duration-300 group-hover:scale-105">
                <Terminal size={20} />
              </span>
              <span className="text-lg font-bold tracking-tight text-text">
                Hash Cracker
              </span>
            </a>
            <p className="max-w-md text-[13px] leading-6 text-text-muted">
              Local, offline password-hash auditing for authorized targets —
              dictionary and bounded brute-force modes, a multiprocessing
              engine, and SQLite history.
            </p>
            <div className="mt-1 flex flex-col gap-1.5">
              <a
                href="/changelog"
                className="group flex w-fit items-center gap-3 text-sm text-text-muted transition-all duration-200 hover:translate-x-1 hover:text-accent"
                aria-label="Open the changelog page"
              >
                <span className="flex h-8 w-8 items-center justify-center rounded-lg border border-border bg-surface-raised/60 text-text-muted transition-colors group-hover:border-accent/30 group-hover:text-accent">
                  <History size={16} aria-hidden="true" />
                </span>
                <span>Changelog</span>
              </a>
              <a
                href="https://github.com/xismail606"
                target="_blank"
                rel="noopener noreferrer"
                className="group flex w-fit items-center gap-3 text-sm text-text-muted transition-all duration-200 hover:translate-x-1 hover:text-accent"
                aria-label="GitHub profile (opens in a new tab)"
              >
                <span className="flex h-8 w-8 items-center justify-center rounded-lg border border-border bg-surface-raised/60 text-text-muted transition-colors group-hover:border-accent/30 group-hover:text-accent">
                  <GitBranch size={16} aria-hidden="true" />
                </span>
                <span>GitHub</span>
              </a>
            </div>
          </div>

          {/* Column 2: On this page */}
          <div className="flex flex-col gap-2.5">
            <h4 className="mono flex items-center gap-2 text-xs font-bold uppercase tracking-[0.16em] text-accent">
              On this page
            </h4>
            <ul className="flex flex-col gap-1.5 text-[13px] text-text-muted">
              {quickLinks.map(({ label, href }) => (
                <li key={href}>
                  <a
                    href={href}
                    className="group inline-flex items-center gap-2 transition-all duration-200 hover:translate-x-1 hover:text-accent"
                  >
                    <ChevronRight
                      size={14}
                      aria-hidden="true"
                      className="text-accent"
                    />
                    {label}
                  </a>
                </li>
              ))}
            </ul>
          </div>

          {/* Column 3: Safety boundaries */}
          <div className="flex flex-col gap-2.5">
            <h4 className="mono flex items-center gap-2 text-xs font-bold uppercase tracking-[0.16em] text-accent">
              Safety
            </h4>
            <ul className="flex flex-col gap-2 text-[13px] text-text-muted">
              {safetyNotes.map(({ Icon, label }) => (
                <li key={label} className="flex items-center gap-2.5">
                  <span className="flex h-7 w-7 shrink-0 items-center justify-center rounded-lg border border-border bg-surface-raised/60 text-text-muted">
                    <Icon size={14} aria-hidden="true" />
                  </span>
                  <span>{label}</span>
                </li>
              ))}
            </ul>
          </div>
        </div>

        {/* Bottom bar */}
        <div className="flex flex-col items-center justify-between gap-3 pt-6 text-xs text-text-muted sm:flex-row">
          <div className="flex items-center gap-2">
            <span className="relative flex h-2 w-2">
              <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-accent opacity-75"></span>
              <span className="relative inline-flex h-2 w-2 rounded-full bg-accent"></span>
            </span>
            <span>
              Made by{" "}
              <a
                href="https://github.com/xismail606"
                target="_blank"
                rel="noopener noreferrer"
                className="font-medium text-text transition-colors hover:text-accent"
              >
                x606
              </a>{" "}
              | Offline Password Auditing
            </span>
          </div>
          <div className="flex items-center gap-4">
            <span>Successful matches are stored locally after acknowledgement.</span>
            <span>&copy; {new Date().getFullYear()} Hash Cracker · MIT License</span>
          </div>
        </div>
      </div>
    </footer>
  );
}
