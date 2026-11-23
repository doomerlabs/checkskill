CREATE TABLE public_url_scan_counts (
  day_utc TEXT NOT NULL,
  source_url TEXT NOT NULL,
  metric TEXT NOT NULL,
  snyk_code TEXT NOT NULL,
  severity TEXT NOT NULL,
  count INTEGER NOT NULL,
  PRIMARY KEY (day_utc, source_url, metric, snyk_code, severity)
) WITHOUT ROWID;

CREATE VIEW scan_counts_export AS
SELECT day_utc, input_type, '' AS source_url, metric, snyk_code, severity, count
FROM scan_counts
UNION ALL
SELECT day_utc, 'public_url' AS input_type, source_url, metric, snyk_code, severity, count
FROM public_url_scan_counts;
