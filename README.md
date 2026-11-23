# CheckSkill

CheckSkill is a free, no-login preflight for agent skills. Paste, edit, or upload a `SKILL.md`, or scan a skill folder, to review security-relevant instructions before publishing or installing it. Findings update as you edit and show exact source spans, the CheckSkill rule, why it matched, and related external checks.

[Skills.sh publishes partner audits](https://www.skills.sh/audits) from Gen Agent Trust Hub, Socket, and Snyk. CheckSkill can check the exact unpublished revision immediately using independent, deterministic rules ported from the offline Markdown audit. CheckSkill’s findings are its own. A clean scan means the rules found no matches. Snyk’s [agent-scan CLI](https://github.com/snyk/agent-scan/blob/main/docs/scanning.md) reads local files and sends them to Snyk’s hosted analysis.

## Agent skill

Install the published skill to have your agent scan a skill folder and recheck it after edits.

```sh
npx skills add https://github.com/doomerlabs/skills --skill check-skill
```

## Terminal

Return JSON findings from a Markdown file.

```sh
curl --fail-with-body -sS \
  -H 'Content-Type: text/markdown' \
  --data-binary @SKILL.md https://checkskill.ai/api/scan
```

The scan endpoint accepts UTF-8 Markdown (`text/markdown`, `text/plain`, or `application/octet-stream`) or `application/json` with a `skill` string.

| Route | Response |
| --- | --- |
| `POST /api/scan` | JSON with `engine`, `findings`, `limited`, and `snykForecast` |
| `POST /api/refs` | The repository, default revision, and branch suggestions for the input |

For a folder scan, POST JSON such as `{"files":[{"path":"SKILL.md","content":"# Example"},{"path":"scripts/setup.sh","content":"# Setup"}]}` to `/api/scan`. Paths must be unique and relative to the skill directory. Package findings include a `path` and file-relative offsets. A missing-manifest finding has no file or source span. Folder uploads scan UTF-8 text and report skipped files. Archive and binary contents are outside the scan's scope.

Paste a public Skills.sh or GitHub link, Gist, or `npx skills add ... --skill ...` command. **Choose revision** lets you enter a branch, tag, or commit. A repository import scans the selected skill folder’s UTF-8 files and reports the exact commit. Use a GitHub folder URL if several folders share the same name.

For API imports, send `{"githubUrl":"https://skills.sh/owner/repo/skill"}` to `/api/refs` to look up branch suggestions. Send the same input to `/api/scan` with an optional `ref`, such as `"feature/preview"`. The scan also returns `files` and `source`.

The deterministic `snykForecast.issues` array contains predicted Snyk `code`, `severity`, and `message` values. `possible` lists lower-confidence codes. Check `limited` and `unmapped` before relying on an empty `issues` array. The forecast is an estimate of the published audit.

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

The checks analyze text. GitHub import fetches public files from the selected skill folder. Scanner references describe related Snyk indicators. CheckSkill uses its own evidence to forecast issues from the given source.

## Privacy and limits

Cloudflare D1 stores [daily scan and finding counts](./docs/scan-analytics.md), including the resolved source URL of public imports. The Worker discards skill contents and detailed findings after responding. API responses carry `Cache-Control: no-store`. Request-body logging and Worker observability are disabled.

Single-file, folder, and GitHub scans accept up to 10 MiB of UTF-8 text. Folders can contain up to 384 text files. Findings mask detected credential literals while preserving their source offsets. The submitted source reaches the Worker before masking. Existing share links still open in the editor.

## Develop and deploy

Use Node.js 22 or later.

```sh
npm ci
npm test
npm run dev
```

`npm run deploy` deploys the production Worker configured in `wrangler.jsonc`.
