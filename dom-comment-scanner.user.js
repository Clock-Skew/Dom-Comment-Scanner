// ==UserScript==
// @name         DOM Comment Scanner
// @namespace    https://github.com/Clock-Skew
// @version      0.1.0
// @description  Local-only rendered DOM review for comments, hidden fields, suspicious attributes, and internal-looking URLs.
// @match        http://*/*
// @match        https://*/*
// @run-at       document-idle
// @grant        none
// @homepageURL  https://github.com/Clock-Skew/dom-comment-scanner
// @supportURL   https://github.com/Clock-Skew/dom-comment-scanner/issues
// @downloadURL  https://raw.githubusercontent.com/Clock-Skew/dom-comment-scanner/main/dom-comment-scanner.user.js
// @updateURL    https://raw.githubusercontent.com/Clock-Skew/dom-comment-scanner/main/dom-comment-scanner.user.js
// ==/UserScript==

(() => {
  "use strict";

  const APP_ID = "dom-comment-scanner";
  const MAX_FINDINGS_PER_KIND = 300;
  const MAX_TEXT_LENGTH = 260;
  const SUSPICIOUS_NAME_PATTERN = /\b(token|secret|api[-_]?key|apikey|auth|bearer|jwt|csrf|xsrf|session|password|passwd|pwd|debug|internal|admin|role|endpoint|env|stage|staging|dev|qa|host|uri|url|redirect|callback)\b/i;
  const INTERNAL_TEXT_PATTERN = /\b(localhost|127\.0\.0\.1|0\.0\.0\.0|10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3}|internal|intranet|staging|stage|dev|qa|sandbox|\.local\b|\.test\b|\.corp\b|\.lan\b)\b/i;
  const URL_PATTERN = /\bhttps?:\/\/[^\s"'<>`]+|\/\/[^\s"'<>`]+/gi;
  const PATH_HINT_PATTERN = /(?:^|[\s"'(])((?:\/|\.\/|\.\.\/)(?:api|admin|internal|debug|dev|staging|qa|v\d+|graphql|oauth|sso|auth)[^\s"'<>`)]+)/gi;
  const URL_ATTRS = new Set([
    "href",
    "src",
    "action",
    "formaction",
    "poster",
    "cite",
    "data-url",
    "data-uri",
    "data-href",
    "data-src",
    "data-endpoint",
    "data-api",
    "data-path"
  ]);

  let latestReport = null;
  let panel = null;

  function trimText(value, length = MAX_TEXT_LENGTH) {
    const text = String(value || "").replace(/\s+/g, " ").trim();
    return text.length > length ? `${text.slice(0, length - 1)}...` : text;
  }

  function cssPath(element) {
    if (!element || element.nodeType !== Node.ELEMENT_NODE) {
      return "document";
    }
    const parts = [];
    let current = element;
    while (current && current.nodeType === Node.ELEMENT_NODE && parts.length < 5) {
      let part = current.localName || current.tagName.toLowerCase();
      if (current.id) {
        part += `#${current.id}`;
        parts.unshift(part);
        break;
      }
      const className = typeof current.className === "string"
        ? current.className.trim().split(/\s+/).filter(Boolean).slice(0, 2).join(".")
        : "";
      if (className) {
        part += `.${className}`;
      }
      const parent = current.parentElement;
      if (parent) {
        const siblings = [...parent.children].filter((child) => child.localName === current.localName);
        if (siblings.length > 1) {
          part += `:nth-of-type(${siblings.indexOf(current) + 1})`;
        }
      }
      parts.unshift(part);
      current = parent;
    }
    return parts.join(" > ");
  }

  function classifyValueShape(value) {
    const text = String(value || "");
    const labels = [];
    if (!text) {
      labels.push("empty");
    }
    if (text.length >= 32) {
      labels.push("long-value");
    }
    if (/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(text)) {
      labels.push("jwt-like");
    }
    if (/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(text)) {
      labels.push("uuid-like");
    }
    if (/^https?:\/\//i.test(text)) {
      labels.push("url-like");
    }
    if (/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(text)) {
      labels.push("email-like");
    }
    if (INTERNAL_TEXT_PATTERN.test(text)) {
      labels.push("internal-looking");
    }
    return labels.length ? labels : ["plain"];
  }

  function sanitizeUrl(raw) {
    const value = String(raw || "").trim().replace(/[),.;]+$/, "");
    if (!value) {
      return null;
    }
    try {
      const base = value.startsWith("//") ? `${location.protocol}${value}` : value;
      const url = new URL(base, location.href);
      if (!["http:", "https:"].includes(url.protocol)) {
        return null;
      }
      const queryKeys = [...new Set([...url.searchParams.keys()])].sort();
      url.hash = "";
      url.search = "";
      if (queryKeys.length) {
        url.search = queryKeys.map((key) => `${encodeURIComponent(key)}=<redacted>`).join("&");
      }
      return {
        url: url.toString(),
        host: url.host,
        origin: url.origin,
        path: url.pathname,
        queryKeys,
        sameOrigin: url.origin === location.origin,
        internalLooking: INTERNAL_TEXT_PATTERN.test(url.toString())
      };
    } catch {
      return null;
    }
  }

  function addFinding(groups, kind, finding) {
    if (groups[kind].length >= MAX_FINDINGS_PER_KIND) {
      return;
    }
    groups[kind].push({
      id: `${kind}-${groups[kind].length + 1}`,
      kind,
      ...finding
    });
  }

  function extractUrlsFromText(text, source, groups, element = null) {
    const seen = new Set();
    for (const match of String(text || "").matchAll(URL_PATTERN)) {
      const sanitized = sanitizeUrl(match[0]);
      if (!sanitized || seen.has(sanitized.url)) {
        continue;
      }
      seen.add(sanitized.url);
      if (sanitized.internalLooking || !sanitized.sameOrigin) {
        addFinding(groups, "urls", {
          severity: sanitized.internalLooking ? "review" : "info",
          title: sanitized.internalLooking ? "Internal-looking URL" : "External URL reference",
          source,
          selector: element ? cssPath(element) : "document",
          value: sanitized.url,
          details: {
            host: sanitized.host,
            path: sanitized.path,
            queryKeys: sanitized.queryKeys,
            sameOrigin: sanitized.sameOrigin
          }
        });
      }
    }

    for (const match of String(text || "").matchAll(PATH_HINT_PATTERN)) {
      const value = trimText(match[1], 180);
      if (!seen.has(value)) {
        seen.add(value);
        addFinding(groups, "urls", {
          severity: "info",
          title: "Endpoint-looking path",
          source,
          selector: element ? cssPath(element) : "document",
          value,
          details: { sameOrigin: true }
        });
      }
    }
  }

  function collectComments(groups) {
    const root = document.documentElement || document;
    const walker = document.createTreeWalker(root, NodeFilter.SHOW_COMMENT);
    while (walker.nextNode()) {
      const node = walker.currentNode;
      const text = trimText(node.nodeValue);
      if (!text) {
        continue;
      }
      const parent = node.parentElement || document.documentElement;
      addFinding(groups, "comments", {
        severity: SUSPICIOUS_NAME_PATTERN.test(text) || INTERNAL_TEXT_PATTERN.test(text) ? "review" : "info",
        title: "HTML comment",
        selector: cssPath(parent),
        value: text,
        details: {
          length: String(node.nodeValue || "").length,
          shape: classifyValueShape(text)
        }
      });
      extractUrlsFromText(text, "comment", groups, parent);
    }
  }

  function collectHiddenFields(groups) {
    document.querySelectorAll('input[type="hidden"]').forEach((field) => {
      const name = field.getAttribute("name") || "";
      const id = field.getAttribute("id") || "";
      const value = field.getAttribute("value") || "";
      const label = name || id || "(unnamed hidden input)";
      addFinding(groups, "hiddenFields", {
        severity: SUSPICIOUS_NAME_PATTERN.test(`${name} ${id}`) || classifyValueShape(value).some((item) => item !== "plain" && item !== "empty") ? "review" : "info",
        title: "Hidden form field",
        selector: cssPath(field),
        value: label,
        details: {
          name: name || undefined,
          id: id || undefined,
          valueLength: value.length,
          valueShape: classifyValueShape(value)
        }
      });
      extractUrlsFromText(value, "hidden-field-value-shape", groups, field);
    });
  }

  function collectSuspiciousAttributes(groups) {
    const elements = document.querySelectorAll("*");
    elements.forEach((element) => {
      for (const attr of element.attributes) {
        const name = attr.name;
        const value = attr.value || "";
        const nameLooksSuspicious = SUSPICIOUS_NAME_PATTERN.test(name);
        const valueLooksInternal = INTERNAL_TEXT_PATTERN.test(value);
        const inlineHandler = /^on[a-z]+$/i.test(name);
        const urlAttribute = URL_ATTRS.has(name.toLowerCase());

        if (nameLooksSuspicious || valueLooksInternal || inlineHandler) {
          addFinding(groups, "attributes", {
            severity: nameLooksSuspicious || inlineHandler ? "review" : "info",
            title: inlineHandler ? "Inline event handler attribute" : "Suspicious attribute",
            selector: cssPath(element),
            value: name,
            details: {
              valueLength: value.length,
              valueShape: classifyValueShape(value),
              rawValue: "<redacted>"
            }
          });
        }

        if (urlAttribute || /^https?:\/\//i.test(value) || value.startsWith("//") || INTERNAL_TEXT_PATTERN.test(value)) {
          extractUrlsFromText(value, `attribute:${name}`, groups, element);
        }
      }
    });
  }

  function buildReport() {
    const groups = {
      comments: [],
      hiddenFields: [],
      attributes: [],
      urls: []
    };

    collectComments(groups);
    collectHiddenFields(groups);
    collectSuspiciousAttributes(groups);

    const allFindings = Object.values(groups).flat();
    const reviewCount = allFindings.filter((finding) => finding.severity === "review").length;
    return {
      version: 1,
      tool: "DOM Comment Scanner",
      scannedAt: new Date().toISOString(),
      page: {
        url: sanitizeUrl(location.href)?.url || location.origin,
        origin: location.origin,
        title: document.title || ""
      },
      counts: {
        total: allFindings.length,
        review: reviewCount,
        comments: groups.comments.length,
        hiddenFields: groups.hiddenFields.length,
        attributes: groups.attributes.length,
        urls: groups.urls.length
      },
      findings: groups
    };
  }

  function makeButton(label, className = "") {
    const button = document.createElement("button");
    button.type = "button";
    button.className = className;
    button.textContent = label;
    return button;
  }

  function injectStyles() {
    if (document.getElementById(`${APP_ID}-styles`)) {
      return;
    }
    const style = document.createElement("style");
    style.id = `${APP_ID}-styles`;
    style.textContent = `
      #${APP_ID}-toggle {
        position: fixed;
        right: 18px;
        bottom: 18px;
        z-index: 2147483647;
        min-width: 118px;
        min-height: 38px;
        border: 1px solid rgba(84, 214, 181, 0.7);
        border-radius: 8px;
        background: #111722;
        color: #f5f7fb;
        font: 13px/1.2 system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
        box-shadow: 0 12px 34px rgba(0, 0, 0, 0.34);
        cursor: pointer;
      }
      #${APP_ID}-panel {
        position: fixed;
        right: 18px;
        bottom: 66px;
        z-index: 2147483647;
        width: min(560px, calc(100vw - 36px));
        max-height: min(720px, calc(100vh - 96px));
        display: grid;
        grid-template-rows: auto auto auto 1fr;
        gap: 10px;
        padding: 14px;
        border: 1px solid rgba(126, 182, 255, 0.44);
        border-radius: 8px;
        background: #10131a;
        color: #f5f7fb;
        font: 13px/1.42 system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
        box-shadow: 0 24px 80px rgba(0, 0, 0, 0.44);
      }
      #${APP_ID}-panel[hidden] { display: none; }
      #${APP_ID}-panel * { box-sizing: border-box; }
      #${APP_ID}-panel h1 { margin: 0; font-size: 17px; letter-spacing: 0; color: #f5f7fb; }
      #${APP_ID}-panel p { margin: 3px 0 0; color: #a8b3c3; }
      #${APP_ID}-panel .vdc-header { display: flex; justify-content: space-between; gap: 10px; align-items: start; }
      #${APP_ID}-panel .vdc-actions { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 7px; }
      #${APP_ID}-panel button, #${APP_ID}-panel select, #${APP_ID}-panel input {
        min-height: 34px;
        border: 1px solid #303a49;
        border-radius: 8px;
        background: #1b2230;
        color: #f5f7fb;
        font: inherit;
      }
      #${APP_ID}-panel button { cursor: pointer; padding: 0 9px; }
      #${APP_ID}-panel button:hover { border-color: #54d6b5; }
      #${APP_ID}-panel .primary { border-color: rgba(84, 214, 181, 0.7); background: rgba(84, 214, 181, 0.16); }
      #${APP_ID}-panel .vdc-summary { display: grid; grid-template-columns: repeat(5, 1fr); gap: 7px; }
      #${APP_ID}-panel .vdc-summary div {
        padding: 8px;
        border: 1px solid #303a49;
        border-radius: 8px;
        background: #171d27;
      }
      #${APP_ID}-panel .vdc-summary strong { display: block; font-size: 18px; color: #f5f7fb; }
      #${APP_ID}-panel .vdc-summary span { color: #a8b3c3; font-size: 11px; }
      #${APP_ID}-panel .vdc-filter { display: grid; grid-template-columns: 1fr 145px; gap: 7px; }
      #${APP_ID}-panel .vdc-results { display: grid; gap: 7px; overflow: auto; min-height: 160px; max-height: 355px; padding-right: 2px; }
      #${APP_ID}-panel .vdc-finding {
        border: 1px solid #303a49;
        border-radius: 8px;
        background: #171d27;
        padding: 9px;
      }
      #${APP_ID}-panel .vdc-finding.review { border-color: rgba(255, 209, 102, 0.58); }
      #${APP_ID}-panel .vdc-finding h2 { margin: 0 0 5px; color: #f5f7fb; font-size: 13px; }
      #${APP_ID}-panel .vdc-finding code {
        display: block;
        margin: 6px 0;
        overflow-wrap: anywhere;
        white-space: pre-wrap;
        color: #dbeafe;
        font: 12px/1.4 ui-monospace, SFMono-Regular, Consolas, "Liberation Mono", monospace;
      }
      #${APP_ID}-panel .vdc-meta { display: flex; flex-wrap: wrap; gap: 5px; margin-top: 7px; }
      #${APP_ID}-panel .vdc-chip {
        border: 1px solid #303a49;
        border-radius: 999px;
        padding: 2px 7px;
        color: #a8b3c3;
        font-size: 11px;
      }
      #${APP_ID}-panel .vdc-chip.review { color: #ffd166; border-color: rgba(255, 209, 102, 0.5); }
      .${APP_ID}-highlight {
        outline: 3px solid #54d6b5 !important;
        outline-offset: 3px !important;
      }
      @media (max-width: 620px) {
        #${APP_ID}-panel .vdc-actions { grid-template-columns: repeat(2, minmax(0, 1fr)); }
        #${APP_ID}-panel .vdc-summary { grid-template-columns: repeat(2, minmax(0, 1fr)); }
        #${APP_ID}-panel .vdc-filter { grid-template-columns: 1fr; }
      }
    `;
    document.documentElement.append(style);
  }

  function allFindings(report = latestReport) {
    if (!report) {
      return [];
    }
    return Object.values(report.findings).flat();
  }

  function findingById(id) {
    return allFindings().find((finding) => finding.id === id);
  }

  function renderFindings() {
    if (!panel || !latestReport) {
      return;
    }
    const results = panel.querySelector(".vdc-results");
    const filter = panel.querySelector(".vdc-search").value.trim().toLowerCase();
    const kind = panel.querySelector(".vdc-kind").value;
    let findings = allFindings();
    if (kind !== "all") {
      findings = findings.filter((finding) => finding.kind === kind);
    }
    if (filter) {
      findings = findings.filter((finding) =>
        `${finding.title} ${finding.selector} ${finding.value} ${JSON.stringify(finding.details || {})}`.toLowerCase().includes(filter)
      );
    }
    results.replaceChildren();
    if (!findings.length) {
      const empty = document.createElement("p");
      empty.textContent = "No findings match this filter.";
      results.append(empty);
      return;
    }
    for (const finding of findings) {
      const item = document.createElement("article");
      item.className = `vdc-finding ${finding.severity}`;
      item.dataset.findingId = finding.id;
      const title = document.createElement("h2");
      title.textContent = finding.title;
      const value = document.createElement("code");
      value.textContent = finding.value || "(no display value)";
      const selector = document.createElement("p");
      selector.textContent = finding.selector;
      const meta = document.createElement("div");
      meta.className = "vdc-meta";
      [finding.kind, finding.severity, finding.source].filter(Boolean).forEach((label) => {
        const chip = document.createElement("span");
        chip.className = `vdc-chip ${label === "review" ? "review" : ""}`;
        chip.textContent = label;
        meta.append(chip);
      });
      const highlight = makeButton("Highlight");
      highlight.addEventListener("click", () => highlightFinding(finding));
      meta.append(highlight);
      item.append(title, value, selector, meta);
      results.append(item);
    }
  }

  function renderSummary() {
    if (!panel || !latestReport) {
      return;
    }
    const summary = panel.querySelector(".vdc-summary");
    const counts = latestReport.counts;
    summary.replaceChildren();
    [
      ["total", counts.total],
      ["review", counts.review],
      ["comments", counts.comments],
      ["hidden", counts.hiddenFields],
      ["attrs", counts.attributes]
    ].forEach(([label, value]) => {
      const node = document.createElement("div");
      const strong = document.createElement("strong");
      strong.textContent = String(value);
      const span = document.createElement("span");
      span.textContent = label;
      node.append(strong, span);
      summary.append(node);
    });
  }

  function runScan() {
    latestReport = buildReport();
    renderSummary();
    renderFindings();
  }

  function exportJson() {
    if (!latestReport) {
      runScan();
    }
    const host = location.host || "page";
    const stamp = latestReport.scannedAt.replace(/[:.]/g, "-");
    const blob = new Blob([JSON.stringify(latestReport, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = `dom-comment-scan-${host}-${stamp}.json`;
    anchor.click();
    URL.revokeObjectURL(url);
  }

  async function copyMarkdown() {
    if (!latestReport) {
      runScan();
    }
    const lines = [
      `# DOM Comment Scanner: ${location.host}`,
      "",
      `- URL: ${latestReport.page.url}`,
      `- Scanned: ${latestReport.scannedAt}`,
      `- Total findings: ${latestReport.counts.total}`,
      `- Review findings: ${latestReport.counts.review}`,
      "",
      "## Findings",
      ...allFindings().map((finding) =>
        `- [${finding.severity}] ${finding.kind}: ${finding.title} at ${finding.selector} - ${finding.value || "(redacted)"}`
      )
    ];
    try {
      await navigator.clipboard.writeText(lines.join("\n"));
    } catch {
      window.prompt("Copy the Markdown report:", lines.join("\n"));
    }
  }

  function highlightFinding(finding) {
    document.querySelectorAll(`.${APP_ID}-highlight`).forEach((node) => node.classList.remove(`${APP_ID}-highlight`));
    if (!finding?.selector || finding.selector === "document") {
      return;
    }
    try {
      const target = document.querySelector(finding.selector.replace(/:nth-of-type\((\d+)\)/g, ":nth-of-type($1)"));
      if (target) {
        target.classList.add(`${APP_ID}-highlight`);
        target.scrollIntoView({ block: "center", behavior: "smooth" });
        window.setTimeout(() => target.classList.remove(`${APP_ID}-highlight`), 2500);
      }
    } catch {
      // Some generated selectors may not be valid if page ids/classes are unusual.
    }
  }

  function buildPanel() {
    injectStyles();
    if (panel) {
      return panel;
    }
    panel = document.createElement("section");
    panel.id = `${APP_ID}-panel`;
    panel.hidden = true;
    panel.innerHTML = `
      <div class="vdc-header">
        <div>
      <h1>DOM Comment Scanner</h1>
          <p>Local rendered DOM review. Values are redacted by design.</p>
        </div>
      </div>
      <div class="vdc-actions"></div>
      <div class="vdc-summary"></div>
      <div class="vdc-filter">
        <input class="vdc-search" type="search" placeholder="Filter findings">
        <select class="vdc-kind">
          <option value="all">All findings</option>
          <option value="comments">Comments</option>
          <option value="hiddenFields">Hidden fields</option>
          <option value="attributes">Attributes</option>
          <option value="urls">URLs</option>
        </select>
      </div>
      <div class="vdc-results"></div>
    `;
    const actions = panel.querySelector(".vdc-actions");
    const scan = makeButton("Scan DOM", "primary");
    const copy = makeButton("Copy Markdown");
    const exportButton = makeButton("Export JSON");
    const close = makeButton("Close");
    actions.append(scan, copy, exportButton, close);
    scan.addEventListener("click", runScan);
    copy.addEventListener("click", copyMarkdown);
    exportButton.addEventListener("click", exportJson);
    close.addEventListener("click", () => { panel.hidden = true; });
    panel.querySelector(".vdc-search").addEventListener("input", renderFindings);
    panel.querySelector(".vdc-kind").addEventListener("change", renderFindings);
    document.documentElement.append(panel);
    return panel;
  }

  function init() {
    if (document.getElementById(`${APP_ID}-toggle`)) {
      return;
    }
    injectStyles();
    const toggle = makeButton("DOM Scan", "");
    toggle.id = `${APP_ID}-toggle`;
    toggle.addEventListener("click", () => {
      const activePanel = buildPanel();
      activePanel.hidden = !activePanel.hidden;
      if (!activePanel.hidden && !latestReport) {
        runScan();
      }
    });
    document.documentElement.append(toggle);
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init, { once: true });
  } else {
    init();
  }
})();
