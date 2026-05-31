# DOM Comment Scanner

[![Tampermonkey Userscript](https://img.shields.io/badge/Tampermonkey-Userscript-00485b?style=for-the-badge&logo=tampermonkey&logoColor=white)](https://www.tampermonkey.net/documentation.php)
[![Grant: None](https://img.shields.io/badge/%40grant-none-16a34a?style=for-the-badge)](https://www.tampermonkey.net/documentation.php?ext=iikm&q=grant&version=4.16.1)
[![Privacy: Local Only](https://img.shields.io/badge/Privacy-Local_Only-0f766e?style=for-the-badge)](PRIVACY.md)
[![No Telemetry](https://img.shields.io/badge/Telemetry-None-111827?style=for-the-badge)](PRIVACY.md)
[![No Network](https://img.shields.io/badge/Network-None-b91c1c?style=for-the-badge)](SECURITY.md)
[![License: MIT](https://img.shields.io/badge/License-MIT-f59e0b?style=for-the-badge)](LICENSE)
[![Static Verify](https://img.shields.io/badge/Static_Verify-Passing-22c55e?style=for-the-badge)](scripts/verify_userscript.py)
[![GitHub Release](https://img.shields.io/github/v/release/Clock-Skew/dom-comment-scanner?style=for-the-badge&logo=github)](https://github.com/Clock-Skew/dom-comment-scanner/releases)
[![shields.io](https://img.shields.io/badge/Badges-shields.io-blue?style=for-the-badge)](https://shields.io/)

![DOM Comment Scanner](a.jpeg)

> A local-only Tampermonkey userscript for rendered DOM review during
> authorized security testing.

DOM Comment Scanner finds HTML comments, hidden form fields, suspicious
attribute names, and internal-looking URLs in the rendered DOM. It runs in the
current tab, shows a local overlay, redacts sensitive values, and exports a
small report for notes.

It does not make network requests. It does not read cookies. It does not read
localStorage or sessionStorage. It does not capture credentials. It does not
upload telemetry.

## Status

Prototype: `0.1.0`

This is a ready-to-use userscript for Tampermonkey-style managers. It is not a
browser extension package and does not require a build step.

## Lawful Use Only

Use this tool only on systems you own, systems you administer, explicit bug
bounty scope, written client scope, or local lab targets.

This project is designed for:

- authorized application security review
- defensive rendered DOM inspection
- bug bounty note preparation
- developer self-review before release
- local lab learning

This project is not designed for unauthorized reconnaissance or exploitation.

## Security Warning

Use only on systems and content you own or are explicitly authorized to test.
Unauthorized scanning or review may violate policy, law, or both.

## Disclaimer

To the maximum extent permitted by law, this project is provided "as is"
without warranties of any kind. The authors and contributors are not liable
for misuse, unauthorized use, or any loss or damage arising from use of this
software.

## What It Scans

The scanner reviews the rendered DOM in the current tab:

- HTML comments from `Document.createTreeWalker(..., NodeFilter.SHOW_COMMENT)`.
- Hidden inputs from `document.querySelectorAll('input[type="hidden"]')`.
- Suspicious attribute names such as token, secret, api-key, auth, jwt, csrf,
  session, debug, internal, admin, endpoint, env, uri, url, redirect, and
  callback.
- Inline event handler attributes such as `onclick`.
- Internal-looking URL strings in comments and selected attributes.
- Endpoint-looking relative paths such as `/api`, `/admin`, `/graphql`, `/auth`,
  `/oauth`, `/sso`, and versioned API paths.

## What It Does Not Scan

- No cookies.
- No localStorage.
- No sessionStorage.
- No IndexedDB.
- No browser history.
- No request bodies.
- No response bodies.
- No password field values.
- No cross-origin iframe contents.
- No background crawling.
- No remote pages.

## Privacy Boundary

The userscript is intentionally declared with:

```javascript
// @grant        none
```

Tampermonkey documents `@grant` as the metadata field for whitelisting `GM_*`
APIs and other powerful features. This script uses `@grant none`, requests no
GM APIs, and contains no Tampermonkey network or storage APIs.

The scanner also avoids:

- `fetch`
- `XMLHttpRequest`
- `WebSocket`
- `EventSource`
- `navigator.sendBeacon`
- `document.cookie`
- `localStorage`
- `sessionStorage`
- `GM_xmlhttpRequest`
- `GM_setValue`
- `GM_getValue`

## Redaction Model

Hidden field and suspicious attribute values are not displayed raw. The scanner
records value metadata instead:

- value length
- value shape labels such as `jwt-like`, `uuid-like`, `url-like`,
  `email-like`, `long-value`, or `internal-looking`
- `<redacted>` markers where raw values would otherwise appear

URL query values are replaced with `<redacted>`. Query parameter names are kept
because they are useful for endpoint and report notes.

## Installation

### Install From GitHub Raw

After this repo is published, open:

```text
https://raw.githubusercontent.com/Clock-Skew/dom-comment-scanner/main/dom-comment-scanner.user.js
```

Tampermonkey should offer to install the script.

### Manual Install

1. Install [Tampermonkey](https://www.tampermonkey.net/).
2. Open the Tampermonkey dashboard.
3. Create a new script.
4. Replace the template with `dom-comment-scanner.user.js`.
5. Save.
6. Visit an authorized HTTP or HTTPS page.
7. Click the **DOM Scan** button in the lower-right corner.

## Usage

1. Open an authorized target page.
2. Click **DOM Scan**.
3. Click **Scan DOM**.
4. Filter by text or finding type.
5. Use **Highlight** to visually outline an associated element when available.
6. Use **Copy Markdown** or **Export JSON** for local notes.

For a local smoke test, serve the included demo page:

```bash
python3 -m http.server 8791
```

Then open:

```text
http://127.0.0.1:8791/demo/test-page.html
```

## Output Format

Example JSON export:

```json
{
  "version": 1,
  "tool": "DOM Comment Scanner",
  "scannedAt": "2026-05-09T14:30:00.000Z",
  "page": {
    "url": "https://example.test/app?view=<redacted>",
    "origin": "https://example.test",
    "title": "Example App"
  },
  "counts": {
    "total": 4,
    "review": 3,
    "comments": 1,
    "hiddenFields": 1,
    "attributes": 1,
    "urls": 1
  },
  "findings": {
    "comments": [
      {
        "kind": "comments",
        "severity": "review",
        "title": "HTML comment",
        "selector": "html > head",
        "value": "TODO internal staging endpoint https://staging.internal.example.test/api/users?token=demo",
        "details": {
          "length": 88,
          "shape": ["internal-looking"]
        }
      }
    ]
  }
}
```

## Verification

Run the local verifier:

```bash
npm run verify
```

The verifier checks:

- userscript metadata block
- `@grant none`
- expected `@match` and `@run-at`
- no network APIs
- no cookie access
- no localStorage/sessionStorage access
- no Tampermonkey GM network/storage APIs
- presence of comment, hidden-field, suspicious-attribute, and URL scan logic
- README safety markers

Also run a syntax check:

```bash
node --check dom-comment-scanner.user.js
```

## Project Layout

```text
.
├── dom-comment-scanner.user.js
├── demo/
│   └── test-page.html
├── scripts/
│   └── verify_userscript.py
├── PRIVACY.md
├── SECURITY.md
├── CONTRIBUTING.md
├── LICENSE
└── package.json
```

## Design Choices

### Userscript Instead Of Extension

This tool does not need extension-level network or host permissions. A
userscript is enough because the task is rendered DOM inspection on the current
page.

### No Raw Hidden Values

Hidden fields often contain CSRF tokens, redirect targets, object IDs, or other
context values. The scanner reports field names, ids, value length, and shape
labels instead of raw values.

### Rendered DOM Only

The scanner sees what the browser currently rendered. It does not fetch source
HTML, spider links, intercept requests, or inspect server responses.

## Limitations

- Dynamic single-page apps may need a re-scan after route changes.
- Closed shadow roots are not inspectable.
- Cross-origin iframe contents are not inspectable.
- Generated selectors may not highlight every element when pages use unusual
  ids or class names.
- Comments stripped during build/minification will not appear.
- Findings are review signals, not vulnerability claims.

## License

MIT. See [LICENSE](LICENSE).
