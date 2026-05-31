# Privacy

DOM Comment Scanner is designed to be local-only.

## What It Reads

When active on a page, the userscript reads the rendered DOM in the current tab:

- HTML comments.
- Hidden input field names, ids, and value shape metadata.
- Attribute names and redacted value metadata.
- URL-looking strings in comments and selected attributes.

## What It Does Not Read

- Cookies.
- localStorage.
- sessionStorage.
- IndexedDB.
- Browser history.
- Keystrokes.
- Password field values.
- Request bodies.
- Response bodies.

## Redaction

Hidden field and suspicious attribute values are not displayed raw. The scanner
records metadata such as length and shape labels, for example `jwt-like`,
`uuid-like`, `url-like`, `long-value`, or `internal-looking`.

URL query values are replaced with `<redacted>` before display or export.

## Transmission

The script does not send data to any remote server. It contains no `fetch`,
`XMLHttpRequest`, `WebSocket`, `EventSource`, `sendBeacon`, or Tampermonkey
network APIs.

## Storage

Findings live in page memory until the tab is closed or reloaded. Export happens
only when the user clicks **Export JSON** or **Copy Markdown**.
