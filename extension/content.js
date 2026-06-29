(function () {
  const STATE = {
    lastText: "",
    lastDecision: null,
    blockCount: 0,
    warnCount: 0
  };

  const COMPOSER_SELECTORS = [
    "#prompt-textarea",
    "textarea[data-id='root']",
    "textarea",
    "[contenteditable='true']"
  ];

  function getComposer() {
    for (const selector of COMPOSER_SELECTORS) {
      const element = document.querySelector(selector);
      if (element && isVisible(element)) return element;
    }
    return null;
  }

  function getComposerText() {
    const composer = getComposer();
    if (!composer) return "";
    if ("value" in composer) return composer.value || "";
    return composer.innerText || composer.textContent || "";
  }

  function isVisible(element) {
    const rect = element.getBoundingClientRect();
    return rect.width > 0 && rect.height > 0;
  }

  function inspectCurrentText() {
    const text = getComposerText();
    STATE.lastText = text;
    STATE.lastDecision = window.AIGuardrailScanner.inspectText(text);
    renderBanner(STATE.lastDecision);
    return STATE.lastDecision;
  }

  function shouldBlockSubmit() {
    const decision = inspectCurrentText();
    return decision.blocked;
  }

  function blockEvent(event, reason) {
    event.preventDefault();
    event.stopPropagation();
    event.stopImmediatePropagation();
    STATE.blockCount += 1;
    saveStats();
    renderBanner({
      ...(STATE.lastDecision || {}),
      blocked: true,
      action: "block",
      message: reason || STATE.lastDecision?.message || "Blocked sensitive data."
    });
    return false;
  }

  function onKeydown(event) {
    if (event.key !== "Enter" || event.shiftKey || event.metaKey || event.ctrlKey || event.altKey) return;
    if (!isInsideComposer(event.target)) return;
    if (shouldBlockSubmit()) blockEvent(event);
  }

  function onClick(event) {
    const button = event.target.closest("button");
    if (!button) return;
    const label = `${button.getAttribute("aria-label") || ""} ${button.textContent || ""}`.toLowerCase();
    const looksLikeSend = label.includes("send") || button.querySelector("svg");
    if (!looksLikeSend) return;
    if (shouldBlockSubmit()) blockEvent(event);
  }

  function onPaste(event) {
    if (!isInsideComposer(event.target)) return;
    const pasted = event.clipboardData?.getData("text") || "";
    const existing = getComposerText();
    const decision = window.AIGuardrailScanner.inspectText(`${existing}\n${pasted}`);
    if (decision.blocked) {
      STATE.lastDecision = decision;
      blockEvent(event, decision.message);
    }
  }

  function onDrop(event) {
    if (!isInsideComposer(event.target)) return;
    const names = [...(event.dataTransfer?.files || [])].map((file) => file.name).join(", ");
    const text = event.dataTransfer?.getData("text") || names;
    const decision = window.AIGuardrailScanner.inspectText(text);
    if (decision.blocked) {
      STATE.lastDecision = decision;
      blockEvent(event, "Blocked risky pasted or dropped content before upload.");
    }
  }

  function isInsideComposer(target) {
    const composer = getComposer();
    return Boolean(composer && (target === composer || composer.contains(target)));
  }

  function renderBanner(decision) {
    let banner = document.getElementById("ai-guardrail-banner");
    if (!banner) {
      banner = document.createElement("div");
      banner.id = "ai-guardrail-banner";
      banner.innerHTML = `
        <div class="ai-guardrail-status"></div>
        <div class="ai-guardrail-body"></div>
        <button type="button" class="ai-guardrail-close" aria-label="Dismiss AI Guardrail alert">×</button>
      `;
      document.documentElement.appendChild(banner);
      banner.querySelector(".ai-guardrail-close").addEventListener("click", () => banner.classList.remove("visible"));
    }

    if (!decision || (!decision.findings?.length && !decision.blocked && !decision.warned)) {
      banner.classList.remove("visible");
      return;
    }

    banner.className = decision.blocked ? "visible blocked" : "visible warned";
    banner.querySelector(".ai-guardrail-status").textContent = decision.blocked ? "AI Guardrail blocked this prompt" : "AI Guardrail warning";
    banner.querySelector(".ai-guardrail-body").innerHTML = `
      <p>${escapeHtml(decision.message)}</p>
      <ul>${(decision.findings || []).slice(0, 4).map((finding) => `<li>${escapeHtml(finding.name)} <span>${escapeHtml(finding.preview)}</span></li>`).join("")}</ul>
    `;
  }

  function saveStats() {
    if (!chrome?.storage?.local) return;
    chrome.storage.local.get({ blockCount: 0, warnCount: 0 }, (stats) => {
      chrome.storage.local.set({
        blockCount: stats.blockCount + STATE.blockCount,
        warnCount: stats.warnCount + STATE.warnCount,
        lastBlockedAt: new Date().toISOString()
      });
      STATE.blockCount = 0;
      STATE.warnCount = 0;
    });
  }

  function escapeHtml(value) {
    return String(value).replace(/[&<>"']/g, (char) => ({
      "&": "&amp;",
      "<": "&lt;",
      ">": "&gt;",
      '"': "&quot;",
      "'": "&#039;"
    })[char]);
  }

  function watchComposer() {
    const composer = getComposer();
    if (!composer || composer.dataset.aiGuardrailAttached === "true") return;
    composer.dataset.aiGuardrailAttached = "true";
    composer.addEventListener("input", () => {
      const decision = inspectCurrentText();
      if (decision.warned) {
        STATE.warnCount += 1;
        saveStats();
      }
    });
  }

  document.addEventListener("keydown", onKeydown, true);
  document.addEventListener("click", onClick, true);
  document.addEventListener("paste", onPaste, true);
  document.addEventListener("drop", onDrop, true);

  watchComposer();
  new MutationObserver(watchComposer).observe(document.documentElement, { childList: true, subtree: true });
})();
