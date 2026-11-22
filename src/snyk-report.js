// Issue titles and severities observed in public Snyk reports on Skills.sh.
const auditIssues = {
  E004: ['CRITICAL', 'Prompt injection detected in skill instructions.'],
  E005: ['CRITICAL', 'Suspicious download URL detected in skill instructions.'],
  E006: ['CRITICAL', 'Malicious code pattern detected in skill scripts.'],
  W007: ['HIGH', 'Insecure credential handling detected in skill instructions.'],
  W008: ['HIGH', 'Secret detected in skill content (API keys, tokens, passwords).'],
  W009: ['MEDIUM', 'Direct money access capability detected (payment gateways, crypto, banking).'],
  W011: ['MEDIUM', 'Third-party content exposure detected (indirect prompt injection risk).'],
  W012: ['MEDIUM', 'Unverifiable external dependency detected (runtime URL that controls agent).'],
  W013: ['MEDIUM', 'Attempt to modify system services in skill instructions.'],
  W021: ['MEDIUM', 'Hidden or invisible Unicode characters detected (potential obfuscation or prompt injection).'],
};

export function isDefiniteSnykFinding({ path, snykEvidence }) {
  return snykEvidence === 'direct' ||
    ((!path || path === 'SKILL.md') &&
      (snykEvidence === 'manifest' || snykEvidence === 'linked-document' || snykEvidence === 'evaluation-prompt' ||
        snykEvidence === 'linked-credential-setup' || snykEvidence === 'requirements-recipe' ||
        snykEvidence === 'obscured-url-example'));
}

export function snykReportFromFindings({ findings, limited }) {
  const codes = new Set();
  const possible = new Set();
  const unmapped = new Set();
  for (const finding of findings) {
    for (const ref of finding.references) {
      const code = ref.name === 'Snyk' && /^([A-Z]\d{3})\b/.exec(ref.code)?.[1];
      if (!code) continue;
      if (!Object.hasOwn(auditIssues, code)) {
        unmapped.add(code);
        continue;
      }
      const direct = isDefiniteSnykFinding(finding);
      (direct ? codes : possible).add(code);
    }
  }
  const issues = [...codes].sort().map(code => {
    const [severity, message] = auditIssues[code];
    return { code, severity, message };
  });
  return { issues, limited, possible: [...possible].filter(code => !codes.has(code)).sort(), unmapped: [...unmapped].sort() };
}
