const increment = `
  INSERT INTO scan_counts (day_utc, input_type, metric, snyk_code, severity, count)
  VALUES (?, ?, ?, ?, ?, ?)
  ON CONFLICT (day_utc, input_type, metric, snyk_code, severity)
  DO UPDATE SET count = count + excluded.count
`;

export async function recordScan(db, inputType, result, forecast) {
  const day = new Date().toISOString().slice(0, 10);
  const upsert = db.prepare(increment);
  const counts = [upsert.bind(day, inputType, 'scans', '', '', 1)];
  if (result.findings.length) {
    counts.push(upsert.bind(day, inputType, 'checkskill_findings', '', '', result.findings.length));
  }
  if (result.limited) counts.push(upsert.bind(day, inputType, 'limited_scans', '', '', 1));
  if (forecast.issues.length) {
    counts.push(upsert.bind(day, inputType, 'scans_with_snyk_findings', '', '', 1));
  }
  for (const { code, severity } of forecast.issues) {
    counts.push(upsert.bind(day, inputType, 'snyk_findings', code, severity, 1));
  }
  await db.batch(counts);
}
