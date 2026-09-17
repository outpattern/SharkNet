(() => {
  const root = document.documentElement;
  const reduceMotion = matchMedia("(prefers-reduced-motion: reduce)").matches;

  const saved = localStorage.getItem("sharknet-site-theme");
  if (saved === "light" || saved === "dark") root.dataset.theme = saved;
  else root.dataset.theme = "dark";

  document.getElementById("themeToggle")?.addEventListener("click", () => {
    root.dataset.theme = root.dataset.theme === "dark" ? "light" : "dark";
    localStorage.setItem("sharknet-site-theme", root.dataset.theme);
  });

  const scrollProgress = document.getElementById("scrollProgress");
  const updateScrollProgress = () => {
    if (!scrollProgress) return;
    const max = Math.max(1, document.documentElement.scrollHeight - window.innerHeight);
    const pct = Math.min(100, Math.max(0, (window.scrollY / max) * 100));
    root.style.setProperty("--scroll-pct", `${pct.toFixed(2)}%`);
  };
  updateScrollProgress();
  window.addEventListener("scroll", updateScrollProgress, { passive: true });
  window.addEventListener("resize", updateScrollProgress);

  const backToTop = document.getElementById("backToTop");
  if (backToTop) {
    const updateBackToTop = () => {
      backToTop.classList.toggle("is-visible", window.scrollY > 520);
    };
    updateBackToTop();
    window.addEventListener("scroll", updateBackToTop, { passive: true });
    backToTop.addEventListener("click", () => {
      window.scrollTo({ top: 0, behavior: reduceMotion ? "auto" : "smooth" });
    });
  }

  document.getElementById("copyHash")?.addEventListener("click", async (e) => {
    const value = document.getElementById("sha")?.textContent?.trim();
    if (!value) return;
    try {
      await navigator.clipboard.writeText(value);
      const old = e.currentTarget.textContent;
      e.currentTarget.textContent = "Copied";
      setTimeout(() => e.currentTarget.textContent = old, 1400);
    } catch {
      e.currentTarget.textContent = "Select & copy";
    }
  });

  // Progressive scroll reveal across the one-page site.
  const revealTargets = [
    ...document.querySelectorAll(
      ".section-head, .feature-card, .mode-card, .flow > div, .requirements-list, .privacy-badge, .privacy-grid > div:last-child, .compare-product, .compare-table-wrap, .install-step, .install-note, .review-summary, .procon-card, .support-card, .download-card, .faq-list details"
    )
  ];
  revealTargets.forEach((el, index) => {
    el.classList.add("reveal");
    el.dataset.delay = String(index % 5);
  });

  if (reduceMotion || !("IntersectionObserver" in window)) {
    revealTargets.forEach((el) => el.classList.add("in-view"));
  } else {
    const revealObserver = new IntersectionObserver(
      (entries, observer) => {
        entries.forEach((entry) => {
          if (!entry.isIntersecting) return;
          entry.target.classList.add("in-view");
          observer.unobserve(entry.target);
        });
      },
      { threshold: 0.12, rootMargin: "0px 0px -7% 0px" }
    );
    revealTargets.forEach((el) => revealObserver.observe(el));
  }

  // Count-up details in the hero to make the value proposition feel alive.
  const counters = [...document.querySelectorAll("[data-count]")];
  const runCounter = (el) => {
    if (el.dataset.counted === "true") return;
    el.dataset.counted = "true";
    const target = Math.max(0, Number(el.dataset.count) || 0);
    if (reduceMotion || target === 0) {
      el.textContent = String(target);
      return;
    }
    const started = performance.now();
    const duration = 950;
    const tick = (now) => {
      const p = Math.min(1, (now - started) / duration);
      const eased = 1 - Math.pow(1 - p, 3);
      el.textContent = String(Math.round(target * eased));
      if (p < 1) requestAnimationFrame(tick);
    };
    requestAnimationFrame(tick);
  };
  counters.forEach((el) => {
    if (!reduceMotion) el.textContent = "0";
  });
  const counterHost = document.querySelector(".hero-metrics");
  if (counterHost && "IntersectionObserver" in window && !reduceMotion) {
    const counterObserver = new IntersectionObserver((entries, observer) => {
      if (!entries.some((entry) => entry.isIntersecting)) return;
      counters.forEach(runCounter);
      observer.disconnect();
    }, { threshold: 0.45 });
    counterObserver.observe(counterHost);
  } else {
    counters.forEach(runCounter);
  }

  // Pointer tilt + moving highlight for cards on precise pointing devices.
  const canTilt = !reduceMotion && matchMedia("(hover: hover) and (pointer: fine)").matches;
  if (canTilt) {
    document.querySelectorAll("[data-tilt]").forEach((card) => {
      card.addEventListener("pointermove", (event) => {
        const rect = card.getBoundingClientRect();
        const x = Math.min(1, Math.max(0, (event.clientX - rect.left) / rect.width));
        const y = Math.min(1, Math.max(0, (event.clientY - rect.top) / rect.height));
        card.style.setProperty("--tilt-y", `${((x - 0.5) * 5).toFixed(2)}deg`);
        card.style.setProperty("--tilt-x", `${((0.5 - y) * 5).toFixed(2)}deg`);
        card.style.setProperty("--mx", `${(x * 100).toFixed(1)}%`);
        card.style.setProperty("--my", `${(y * 100).toFixed(1)}%`);
      });
      card.addEventListener("pointerleave", () => {
        card.style.setProperty("--tilt-x", "0deg");
        card.style.setProperty("--tilt-y", "0deg");
        card.style.setProperty("--mx", "50%");
        card.style.setProperty("--my", "50%");
      });
    });

    const heroTilt = document.querySelector("[data-hero-tilt]");
    const heroVisual = document.querySelector(".hero-visual");
    if (heroTilt && heroVisual) {
      heroVisual.addEventListener("pointermove", (event) => {
        const rect = heroVisual.getBoundingClientRect();
        const x = (event.clientX - rect.left) / rect.width - 0.5;
        const y = (event.clientY - rect.top) / rect.height - 0.5;
        heroTilt.style.transform = `perspective(1200px) rotateY(${(-3 + x * 3.2).toFixed(2)}deg) rotateX(${(1 - y * 2.4).toFixed(2)}deg) translate3d(${(x * 5).toFixed(1)}px, ${(-y * 5).toFixed(1)}px, 0)`;
      });
      heroVisual.addEventListener("pointerleave", () => {
        heroTilt.style.transform = "perspective(1200px) rotateY(-3deg) rotateX(1deg)";
      });
    }
  }

  // Highlight the nav item for the section currently moving through the viewport.
  const navLinks = [...document.querySelectorAll('.desktop-nav a[href^="#"]')];
  const navMap = new Map(navLinks.map((link) => [link.getAttribute("href").slice(1), link]));
  const navSections = [...navMap.keys()].map((id) => document.getElementById(id)).filter(Boolean);
  if ("IntersectionObserver" in window && navSections.length) {
    const navObserver = new IntersectionObserver((entries) => {
      const visible = entries
        .filter((entry) => entry.isIntersecting)
        .sort((a, b) => b.intersectionRatio - a.intersectionRatio)[0];
      if (!visible) return;
      navLinks.forEach((link) => link.classList.remove("active"));
      navMap.get(visible.target.id)?.classList.add("active");
    }, { rootMargin: "-25% 0px -58% 0px", threshold: [0.01, 0.15, 0.35] });
    navSections.forEach((section) => navObserver.observe(section));
  }
})();
