function incrementCounts(table, dimensions) {
  return `
    INSERT INTO ${table} (${dimensions}, metric, snyk_code, severity, count)
    VALUES (?, ?, ?, ?, ?, ?)
    ON CONFLICT (${dimensions}, metric, snyk_code, severity)
    DO UPDATE SET count = count + excluded.count
  `;
}

const increment = incrementCounts('scan_counts', 'day_utc, input_type');
const incrementUrl = incrementCounts('public_url_scan_counts', 'day_utc, source_url');

function scannedSourceUrl({ project, commit, folder, gist, gistFile }) {
  if (gist) return `https://gist.github.com/${project}/${commit}?` + new URLSearchParams({ file: gistFile });
  const path = folder.split('/').map(encodeURIComponent).join('/');
  return `https://github.com/${project}/tree/${commit}${path ? '/' + path : ''}`;
}

export async function recordScan(db, inputType, result, forecast, source) {
  const day = new Date().toISOString().slice(0, 10);
  const upsert = db.prepare(source ? incrementUrl : increment);
  const dimension = source ? scannedSourceUrl(source) : inputType;
  const counts = [upsert.bind(day, dimension, 'scans', '', '', 1)];
  if (result.findings.length) {
    counts.push(upsert.bind(day, dimension, 'checkskill_findings', '', '', result.findings.length));
  }
  if (result.limited) counts.push(upsert.bind(day, dimension, 'limited_scans', '', '', 1));
  if (forecast.issues.length) {
    counts.push(upsert.bind(day, dimension, 'scans_with_snyk_findings', '', '', 1));
  }
  for (const { code, severity } of forecast.issues) {
    counts.push(upsert.bind(day, dimension, 'snyk_findings', code, severity, 1));
  }
  await db.batch(counts);
}
