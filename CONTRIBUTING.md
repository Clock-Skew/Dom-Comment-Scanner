# Contributing

Contributions are welcome when they preserve the project boundary: local-only,
rendered DOM review for authorized testing.

## Ground Rules

- Keep `@grant none`.
- Do not add network APIs.
- Do not add cookies or storage reads.
- Do not expose raw hidden field values by default.
- Do not add payload injection, fuzzing, crawling, or exploitation features.
- Prefer redacted metadata over sensitive values.
- Document any new finding class in the README and verifier.

## Development

```bash
npm run verify
```

The verifier is intentionally simple and dependency-free.
