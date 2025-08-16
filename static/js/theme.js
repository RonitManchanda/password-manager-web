// static/js/theme.js

(function () {
  const root = document.documentElement;
  const btn  = document.getElementById("theme-toggle");

  // Apply a theme to <html data-theme="...">
  function applyTheme(t) {
    root.setAttribute("data-theme", t);
  }

  // Button label + a11y
  function paintButton(t) {
    if (!btn) return;
    const next = t === "dark" ? "light" : "dark";
    btn.setAttribute("aria-label", `Switch to ${next} theme`);
    btn.setAttribute("aria-pressed", String(t === "light"));
    // Simple text; keep CSP-friendly (no SVG injection)
    btn.textContent = t === "dark" ? "Theme: Dark" : "Theme: Light";
  }

  // Resolve initial theme: saved -> system -> dark
  const stored = (() => {
    try { return localStorage.getItem("theme"); } catch { return null; }
  })();

  const systemPrefersDark =
    typeof window !== "undefined" &&
    window.matchMedia &&
    window.matchMedia("(prefers-color-scheme: dark)").matches;

  const initial = stored || (systemPrefersDark ? "dark" : "light");
  applyTheme(initial);
  paintButton(initial);

  // Toggle on click
  if (btn) {
    btn.addEventListener("click", () => {
      const curr = root.getAttribute("data-theme") === "light" ? "light" : "dark";
      const next = curr === "dark" ? "light" : "dark";
      applyTheme(next);
      paintButton(next);
      try { localStorage.setItem("theme", next); } catch {}
    });
  }

  // If user didn’t set a preference, follow system changes live
  if (!stored && window.matchMedia) {
    const mql = window.matchMedia("(prefers-color-scheme: dark)");
    const onChange = (e) => {
      const t = e.matches ? "dark" : "light";
      applyTheme(t);
      paintButton(t);
    };
    // Safari <14 uses addListener
    if (mql.addEventListener) mql.addEventListener("change", onChange);
    else if (mql.addListener) mql.addListener(onChange);
  }
})();
