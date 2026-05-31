# Security Policy

## Supported Scope

This userscript is for lawful, authorized security testing, defensive review,
bug bounty work, and local lab learning.

Do not use it against systems you do not own or do not have explicit permission
to test.

## Design Boundaries

- Rendered DOM scan only.
- No network calls.
- No storage API reads.
- No cookie reads.
- No credential collection.
- No raw hidden field values by default.
- No telemetry.
- No remote upload.
- No exploit payloads.
- No crawling.

The injected panel and highlight outline are visual-only page overlays for the
current tab.

## Reporting Issues

Open a GitHub issue with:

- browser name and version
- userscript manager and version
- the page type or a local reproduction file
- expected behavior
- actual behavior

Do not include private target URLs, secrets, cookies, tokens, or credentials in
public issues.
