# CheckSkill

CheckSkill is a free, no-login preflight for agent skills. Paste, edit, or upload a `SKILL.md`, or scan a skill folder, to review security-relevant instructions before publishing or installing it. Findings update as you edit and show exact source spans, the CheckSkill rule, why it matched, and related external checks.

[Skills.sh publishes partner audits](https://www.skills.sh/audits) from Gen Agent Trust Hub, Socket, and Snyk. CheckSkill can check the exact unpublished revision immediately using independent, deterministic rules ported from the offline Markdown audit. CheckSkill’s findings are its own. A clean scan means the rules found no matches. Snyk’s [agent-scan CLI](https://github.com/snyk/agent-scan/blob/main/docs/scanning.md) reads local files and sends them to Snyk’s hosted analysis.

## Terminal

Return JSON findings from a Markdown file.

```sh
curl --fail-with-body -sS \
  -H 'Content-Type: text/markdown' \
  --data-binary @SKILL.md https://checkskill.ai/api/scan
```

Open a prefilled editor on macOS. Use `xdg-open` on Linux.

```sh
link=$(curl -fsS \
  -H 'Content-Type: text/markdown' \
  --data-binary @SKILL.md https://checkskill.ai/api/open) && open "$link"
```

All three endpoints accept UTF-8 Markdown (`text/markdown`, `text/plain`, or `application/octet-stream`) or `application/json` with a `skill` string.

| Route | Response |
| --- | --- |
| `POST /api/scan` | JSON with `engine`, `findings`, and `limited` |
| `POST /api/share` | JSON with a `url` string |
| `POST /api/open` | A plain-text share URL followed by a newline |

For a folder scan, POST JSON such as `{"files":[{"path":"SKILL.md","content":"# Example"},{"path":"scripts/setup.sh","content":"# Setup"}]}` to `/api/scan`. Paths must be unique and relative to the skill directory. Package findings include a `path` and file-relative offsets. A missing-manifest finding has no file or source span. Folder uploads scan UTF-8 text and report skipped files. Archive and binary contents are outside the scan's scope.

Each finding includes a local rule ID, an assessment, a severity, an explanation, related scanner checks, and one or more evidence spans. Offsets use UTF-16 code units, with an inclusive `start` and exclusive `end`. Line and column numbers start at 1. The scan returns up to 100 findings and sets `limited` when additional findings are omitted. Errors return a non-success HTTP status and JSON with an `error` field.

## Skill rule coverage

CheckSkill has independent rules linked to all ten skill indicators in [Snyk’s current catalog](https://github.com/snyk/agent-scan/blob/main/docs/risks.md#skill-risks) and the legacy [hidden Unicode check](https://github.com/snyk/agent-scan/blob/main/docs/issue-codes.md#W021).

| Snyk indicator | CheckSkill evidence |
| --- | --- |
| `prompt_injection_skill_instructions` (E004) | Role overrides, consent bypass, and concealment wording |
| `suspicious_download_url` (E005) | Obscured artifact source or an artifact download with no visible integrity check |
| `malicious_code` (E006) | Suspicious execution, persistence, or sensitive outbound-transfer patterns |
| `insecure_credential_handling` (W007) | Secret values directed to output, commands, or plaintext storage |
| `secret_detection` (W008) | Credential-like literals and private-key markers, with masked evidence |
| `direct_money_access` (W009) | Instructions that can initiate or authorize a transaction |
| `third_party_content_exposure` (W011) | Ingestion of public or externally controlled content |
| `unverifiable_dependencies` (W012) | Mutable remote instructions or executable artifacts used at runtime |
| `modifying_system_services` (W013) | Commands or instructions that can modify system state |
| `missing_skill_md` (W014) | No root manifest in a submitted skill folder |
| Hidden Unicode (W021, legacy) | Invisible format or control characters |

These checks analyze text and do not fetch URLs, verify credential validity, or execute supplied files. Scanner references describe related Snyk indicators. CheckSkill uses its own evidence and does not reproduce Snyk’s hosted classifiers or scoring.

## Privacy and limits

The Worker receives skills to process requests and discards the text and findings after responding. API responses carry `Cache-Control: no-store`. There are no database or storage bindings, analytics scripts, or application request-body logs. Worker observability is disabled in the Wrangler configuration.

The scan limit is 64 KiB of UTF-8 source, across up to 64 files for a folder scan. Findings mask detected credential literals while preserving their source offsets. The submitted source reaches the Worker before masking. Share links have a separate limit of 24,000 base64url characters for the gzipped source. Share links support single-file scans. The unlisted link itself contains the skill in its URL fragment. Anyone with the link can read it. Opening a link fills the editor and triggers a scan.

## Develop and deploy

Use Node.js 22 or later.

```sh
npm ci
npm test
npm run dev
```

Deploy with `npm run deploy` after authenticating Wrangler and setting `CLOUDFLARE_ACCOUNT_ID` to the verified replicated.com Cloudflare account. The `checkskill.ai` zone must be active in that account. Wrangler attaches the Worker to the custom domain configured in [wrangler.jsonc](./wrangler.jsonc). See [Cloudflare’s custom-domain documentation](https://developers.cloudflare.com/workers/configuration/routing/custom-domains/).
