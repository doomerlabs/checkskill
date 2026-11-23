import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('../', import.meta.url));
const fields = ['day_utc', 'input_type', 'source_url', 'metric', 'snyk_code', 'severity', 'count'];
const query = `SELECT ${fields.join(', ')} FROM scan_counts_export ORDER BY ${fields.slice(0, -1).join(', ')}`;
const wrangler = fileURLToPath(new URL('../node_modules/wrangler/bin/wrangler.js', import.meta.url));
const output = execFileSync(process.execPath, [wrangler, 'd1', 'execute', 'SCAN_ANALYTICS',
  '--remote', '--json', '--command', query], { cwd: root, encoding: 'utf8' });
const [{ success, results }] = JSON.parse(output);
if (!success || !Array.isArray(results)) throw new Error('Cloudflare did not return the scan counts.');

const csvCell = value => /[",\r\n]/.test(value) ? '"' + value.replaceAll('"', '""') + '"' : value;
process.stdout.write(fields.join(',') + '\n');
for (const row of results) {
  process.stdout.write(fields.map(field => csvCell(String(row[field] ?? ''))).join(',') + '\n');
}
