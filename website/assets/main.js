async function initializeWebsite() {
  const { t } = await import("./i18n.js");

  function initializeCopyButtons() {
    document.querySelectorAll("[data-copy]").forEach((button) => {
      const label = button.textContent;
      button.addEventListener("click", async () => {
        const target = document.getElementById(
          button.getAttribute("data-copy"),
        );
        if (target === null) return;

        const status = document.getElementById("copy-status");
        const content = target.textContent.trim();
        const text =
          target.closest(".terminal-prompt") === null
            ? content
            : content.replace(/\s+/g, " ");
        try {
          await navigator.clipboard.writeText(text);
          button.textContent = t("Copied");
          if (status !== null)
            status.textContent = t("Code copied to clipboard.");
        } catch {
          const range = document.createRange();
          range.selectNodeContents(target);
          const selection = window.getSelection();
          if (selection !== null) {
            selection.removeAllRanges();
            selection.addRange(range);
          }
          button.textContent = t("Selected");
          if (status !== null)
            status.textContent = t(
              "Code selected. Use your keyboard to copy it.",
            );
        }

        window.setTimeout(() => {
          button.textContent = label;
        }, 2000);
      });
    });
  }

  initializeCopyButtons();

  function initializeStepComparisons() {
    document
      .querySelectorAll("[data-step-comparison]")
      .forEach((comparison) => {
        const buttons = comparison.querySelectorAll("[data-select-step]");
        const selectStep = (button) => {
          const selected = button.getAttribute("data-select-step");
          buttons.forEach((candidate) => {
            candidate.setAttribute(
              "aria-pressed",
              String(candidate === button),
            );
          });
          comparison.querySelectorAll("[data-step]").forEach((fragment) => {
            fragment.classList.toggle(
              "is-active",
              fragment.getAttribute("data-step") === selected,
            );
          });
          comparison.querySelectorAll("[data-step-note]").forEach((note) => {
            note.hidden = note.getAttribute("data-step-note") !== selected;
          });
        };
        buttons.forEach((button) => {
          button.addEventListener("click", () => selectStep(button));
        });
        const initial = Array.from(buttons).find(
          (button) => button.getAttribute("aria-pressed") === "true",
        );
        if (initial) selectStep(initial);
      });
  }

  initializeStepComparisons();

  function initializeLinkedDetails() {
    const gap = 16;

    // The sticky "On this page" bar covers the top of the viewport, so anchors
    // have to clear it. A fixed side panel does not overlap the content.
    const stickyHeight = () => {
      const nav = document.querySelector(".home-page-nav");
      if (nav === null) return 0;
      const position = window.getComputedStyle(nav).position;
      if (position !== "sticky") return 0;
      return Math.round(nav.getBoundingClientRect().height);
    };

    const revealTarget = (fragment, behavior = "smooth") => {
      if (!fragment.startsWith("#")) return false;
      let id;
      try {
        id = decodeURIComponent(fragment.slice(1));
      } catch {
        return false;
      }
      const target = document.getElementById(id);
      if (target === null) return false;

      // Open collapsed details that contain the target before measuring it.
      for (let element = target; element; element = element.parentElement) {
        if (element instanceof HTMLDetailsElement) element.open = true;
      }

      const reduceMotion = window.matchMedia(
        "(prefers-reduced-motion: reduce)",
      ).matches;
      const top =
        target.getBoundingClientRect().top +
        window.scrollY -
        stickyHeight() -
        gap;
      window.scrollTo({
        top: Math.max(top, 0),
        behavior: reduceMotion ? "auto" : behavior,
      });
      return true;
    };

    document.querySelectorAll('a[href^="#"]').forEach((link) => {
      link.addEventListener("click", (event) => {
        const fragment = link.getAttribute("href");
        if (!revealTarget(fragment)) return;
        event.preventDefault();
        // Keep the URL shareable without letting the browser jump again.
        window.history.pushState(null, "", fragment);
        // Let the page navigation know the active entry changed.
        window.dispatchEvent(new Event("website-anchor-change"));
        const target = document.getElementById(
          decodeURIComponent(fragment.slice(1)),
        );
        const heading = target?.querySelector("h2") ?? target;
        heading?.setAttribute("tabindex", "-1");
        heading?.focus({ preventScroll: true });
      });
    });

    window.addEventListener("hashchange", () =>
      revealTarget(window.location.hash),
    );

    // A link that arrives with a hash needs the same offset as a click.
    if (window.location.hash !== "") {
      window.requestAnimationFrame(() =>
        revealTarget(window.location.hash, "auto"),
      );
    }
  }

  initializeLinkedDetails();

  function initializeBackToTop() {
    const link = document.querySelector(".back-to-top");
    if (link === null) return;

    const updateVisibility = () => {
      link.hidden = window.scrollY < 400;
    };
    window.addEventListener("scroll", updateVisibility, { passive: true });
    updateVisibility();

    link.addEventListener("click", (event) => {
      event.preventDefault();
      const reduceMotion = window.matchMedia(
        "(prefers-reduced-motion: reduce)",
      ).matches;
      window.scrollTo({ top: 0, behavior: reduceMotion ? "auto" : "smooth" });
      document
        .querySelector(".brand, .breadcrumb a")
        ?.focus({ preventScroll: true });
    });
  }

  initializeBackToTop();

  async function initializeGitHubStars() {
    const link = document.querySelector(".nav-github");
    const count = link?.querySelector(".nav-github-count");
    if (count === null || count === undefined) return;

    try {
      const response = await fetch("https://api.github.com/repos/kushvinth/crowbar", {
        headers: { Accept: "application/vnd.github+json" },
        credentials: "omit",
        signal: AbortSignal.timeout(5000),
      });
      if (!response.ok) return;
      const repository = await response.json();
      const stars = repository.stargazers_count;
      if (!Number.isSafeInteger(stars) || stars < 0) return;

      const formatted = new Intl.NumberFormat(
        document.documentElement.lang,
      ).format(stars);
      const label = t("crowbar on GitHub ({count})", { count: formatted });
      count.textContent = formatted;
      count.hidden = false;
      link.setAttribute("aria-label", label);
      link.setAttribute("title", label);
    } catch {
      // Keep the repository link usable when GitHub is unavailable.
    }
  }

  initializeGitHubStars();

  function initializeDemoPlayer() {
    const player = document.querySelector("[data-demo-player]");
    if (player === null || !window.IntersectionObserver) return;

    let loaded = false;
    const observer = new IntersectionObserver(
      (entries) => {
        entries.forEach((entry) => {
          if (!entry.isIntersecting || loaded) return;
          loaded = true;
          observer.disconnect();

          const link = document.createElement("link");
          link.rel = "stylesheet";
          link.href =
            "https://cdn.jsdelivr.net/npm/asciinema-player@3.8.0/dist/bundle/asciinema-player.css";
          document.head.appendChild(link);

          const script = document.createElement("script");
          script.src =
            "https://cdn.jsdelivr.net/npm/asciinema-player@3.8.0/dist/bundle/asciinema-player.min.js";
          script.addEventListener("load", () => {
            window.AsciinemaPlayer.create(player.dataset.demoPlayer, player, {
              autoPlay: true,
              loop: true,
              fit: "width",
              idleTimeLimit: 2,
              theme: "asciinema",
            });
          });
          document.body.appendChild(script);
        });
      },
      { rootMargin: "200px" },
    );
    observer.observe(player);
  }

  initializeDemoPlayer();
}

initializeWebsite();
