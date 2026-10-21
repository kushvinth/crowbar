import { t } from "./i18n.js";

function initializeHomeNavigation() {
  const menu = document.querySelector("[data-home-nav]");
  if (menu === null) return;
  const currentLabel = menu.querySelector("[data-home-nav-current]");
  if (currentLabel === null) return;
  const wideScreen = window.matchMedia("(min-width: 1440px)");
  const entries = Array.from(menu.querySelectorAll('a[href^="#"]'))
    .map((link) => ({
      link,
      target: document.getElementById(link.getAttribute("href").slice(1)),
    }))
    .filter((entry) => entry.target !== null);
  if (entries.length === 0) return;

  const updatePosition = () => {
    const offset = wideScreen.matches ? 40 : 88;
    let current = entries[0];
    entries.forEach((entry) => {
      if (entry.target.getBoundingClientRect().top <= offset) current = entry;
    });
    // Prefer the entry named in the address bar while it is on screen. The
    // last section cannot scroll to the top of the viewport, so the scroll
    // position alone never marks it as current.
    const selected = entries.find(
      (entry) => entry.link.hash === window.location.hash,
    );
    const selectedTop = selected?.target.getBoundingClientRect().top;
    if (
      selected !== undefined &&
      selectedTop >= 0 &&
      selectedTop < window.innerHeight
    ) {
      current = selected;
    } else if (
      window.scrollY + window.innerHeight >=
      document.documentElement.scrollHeight - 2
    ) {
      current = entries[entries.length - 1];
    }
    entries.forEach((entry) => {
      if (entry === current)
        entry.link.setAttribute("aria-current", "location");
      else entry.link.removeAttribute("aria-current");
    });
    currentLabel.textContent = current.link.textContent;
  };
  const updateLayout = () => {
    menu.open = wideScreen.matches;
    updatePosition();
  };
  let scheduled = false;
  const schedulePosition = () => {
    if (scheduled) return;
    scheduled = true;
    window.requestAnimationFrame(() => {
      scheduled = false;
      updatePosition();
    });
  };
  entries.forEach(({ link, target }) => {
    link.addEventListener("click", () => {
      // Collapse the dropdown on narrow screens. The scroll itself is handled
      // by the shared anchor navigation in main.js.
      if (!wideScreen.matches) menu.open = false;
    });
  });
  wideScreen.addEventListener("change", updateLayout);
  window.addEventListener("scroll", schedulePosition, { passive: true });
  window.addEventListener("resize", schedulePosition, { passive: true });
  window.addEventListener("hashchange", schedulePosition);
  window.addEventListener("load", schedulePosition);
  // A smooth scroll settles after the last scroll event, so recompute once it
  // finishes and once more after a short delay as a fallback.
  window.addEventListener("scrollend", schedulePosition);
  window.addEventListener("website-anchor-change", () => {
    window.setTimeout(schedulePosition, 450);
  });
  updateLayout();
}

initializeHomeNavigation();
