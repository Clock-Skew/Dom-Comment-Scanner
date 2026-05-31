#!/usr/bin/env python3
"""Static verification for DOM Comment Scanner."""

from __future__ import annotations

import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "dom-comment-scanner.user.js"
README = ROOT / "README.md"

FORBIDDEN_PATTERNS = {
    "fetch(": r"\bfetch\s*\(",
    "XMLHttpRequest": r"\bXMLHttpRequest\b",
    "WebSocket": r"\bWebSocket\b",
    "EventSource": r"\bEventSource\b",
    "sendBeacon": r"\bsendBeacon\s*\(",
    "document.cookie": r"\bdocument\.cookie\b",
    "localStorage": r"\blocalStorage\b",
    "sessionStorage": r"\bsessionStorage\b",
    "GM_xmlhttpRequest": r"\bGM_xmlhttpRequest\b",
    "GM_setValue": r"\bGM_setValue\b",
    "GM_getValue": r"\bGM_getValue\b",
    "GM_download": r"\bGM_download\b",
    "unsafeWindow": r"\bunsafeWindow\b",
}


def fail(message: str) -> None:
    print(f"verify_userscript: {message}", file=sys.stderr)
    raise SystemExit(1)


def assert_metadata(text: str) -> None:
    if "// ==UserScript==" not in text or "// ==/UserScript==" not in text:
        fail("metadata block is missing")
    required = [
        "// @name         DOM Comment Scanner",
        "// @version      0.1.0",
        "// @match        http://*/*",
        "// @match        https://*/*",
        "// @run-at       document-idle",
        "// @grant        none",
        "// @downloadURL",
        "// @updateURL",
    ]
    for marker in required:
        if marker not in text:
            fail(f"metadata missing marker: {marker}")


def assert_no_forbidden_apis(text: str) -> None:
    stripped = re.sub(r"//.*|/\*[\s\S]*?\*/|`[^`]*`|'[^']*'|\"[^\"]*\"", "", text)
    for label, pattern in FORBIDDEN_PATTERNS.items():
        if re.search(pattern, stripped):
            fail(f"forbidden API found: {label}")


def assert_required_logic(text: str) -> None:
    required = [
        "NodeFilter.SHOW_COMMENT",
        "createTreeWalker",
        "input[type=\"hidden\"]",
        "SUSPICIOUS_NAME_PATTERN",
        "INTERNAL_TEXT_PATTERN",
        "<redacted>",
        "navigator.clipboard.writeText",
        "Blob",
        "URL.createObjectURL",
    ]
    for marker in required:
        if marker not in text:
            fail(f"script missing marker: {marker}")


def assert_readme() -> None:
    text = README.read_text(encoding="utf-8")
    required = [
        "Lawful Use Only",
        "@grant none",
        "No cookies",
        "No localStorage",
        "No sessionStorage",
        "No Network",
        "shields.io",
        "Tampermonkey",
    ]
    for marker in required:
        if marker not in text:
            fail(f"README missing marker: {marker}")


def main() -> int:
    text = SCRIPT.read_text(encoding="utf-8")
    assert_metadata(text)
    assert_no_forbidden_apis(text)
    assert_required_logic(text)
    assert_readme()
    print("dom comment scanner static verification passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
