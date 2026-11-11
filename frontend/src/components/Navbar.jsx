import { useEffect, useRef, useState } from "react";
import { GitBranch, Sun, Moon, Terminal, History } from "lucide-react";
import ChangelogModal from "./ChangelogModal";

// Fixed floating capsule navbar, adapted from the Hash Cracker webpage landing navbar:
// logo pill on the left, action pill on the right, hides on scroll down.
export default function Navbar() {
  const [theme, setTheme] = useState(
    typeof document !== "undefined"
      ? document.documentElement.getAttribute("data-theme") || "dark"
      : "dark"
  );
  const [navVisible, setNavVisible] = useState(true);
  const [changelogOpen, setChangelogOpen] = useState(false);
  const prevScrollPos = useRef(0);

  useEffect(() => {
    const handleScroll = () => {
      const currentScrollPos = window.scrollY;
      const scrollingDown = currentScrollPos > prevScrollPos.current;
      const pastThreshold = currentScrollPos > 80;
      const delta = Math.abs(currentScrollPos - prevScrollPos.current);
      if (delta > 10) {
        setNavVisible(!(scrollingDown && pastThreshold));
        prevScrollPos.current = currentScrollPos;
      }
    };
    window.addEventListener("scroll", handleScroll, { passive: true });
    return () => window.removeEventListener("scroll", handleScroll);
  }, []);

  const toggleTheme = () => {
    const next = theme === "dark" ? "light" : "dark";
    setTheme(next);
    const root = document.documentElement;
    root.setAttribute("data-theme", next);
    localStorage.setItem("theme", next);
    const meta = document.getElementById("meta-theme-color");
    if (meta) meta.setAttribute("content", next === "dark" ? "#08090c" : "#f2f4f8");
  };

  return (
    <header
      className={`nav-capsule ${navVisible ? "" : "nav-capsule--hidden"}`}
    >
      <div className="nav-capsule-inner">
        {/* Brand logo pill */}
        <a
          href="/"
          className="nav-logo-pill group"
          aria-label="Hash Cracker home"
        >
          <span className="flex h-8 w-8 items-center justify-center rounded-full border border-accent/30 bg-accent/10 text-accent">
            <Terminal size={16} />
          </span>
          <span className="text-sm font-bold tracking-tight text-text">
            Hash Cracker
          </span>
        </a>

        {/* Action controls inside capsule pill */}
        <nav className="nav-pill" aria-label="Dashboard controls">
          <button
            onClick={() => setChangelogOpen(true)}
            title="View changelog"
            className="pill-link"
            type="button"
            aria-label="View changelog"
          >
            <History size={18} />
          </button>
          <a
            href="https://github.com/xismail606/Hash-Cracker"
            target="_blank"
            rel="noopener noreferrer"
            title="GitHub Repository"
            className="pill-link"
            aria-label="GitHub Repository (opens in a new tab)"
          >
            <GitBranch size={18} />
          </a>
          <button
            onClick={toggleTheme}
            title={theme === "dark" ? "Switch to light mode" : "Switch to dark mode"}
            className="pill-cta theme-toggle active:scale-95"
            type="button"
            aria-label="Toggle visual theme"
          >
            <div
              className={`transition-all duration-500 ${
                theme === "dark" ? "rotate-[360deg]" : "rotate-0"
              }`}
            >
              {theme === "dark" ? <Sun size={18} /> : <Moon size={18} />}
            </div>
          </button>
        </nav>
      </div>

      <ChangelogModal isOpen={changelogOpen} onClose={() => setChangelogOpen(false)} />
    </header>
  );
}
