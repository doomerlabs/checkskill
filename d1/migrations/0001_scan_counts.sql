CREATE TABLE scan_counts (
  day_utc TEXT NOT NULL,
  input_type TEXT NOT NULL,
  metric TEXT NOT NULL,
  snyk_code TEXT NOT NULL,
  severity TEXT NOT NULL,
  count INTEGER NOT NULL,
  PRIMARY KEY (day_utc, input_type, metric, snyk_code, severity)
) WITHOUT ROWID;
