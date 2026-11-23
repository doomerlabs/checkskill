# Scan analytics

CheckSkill counts successful scans by UTC date and input type. A rescan counts again.
Public imports are grouped by the resolved GitHub folder or Gist URL at the scanned commit. Earlier public scans and all scans of submitted content have a blank URL.
The four input types are `markdown` for pasted or API text, `file` for the initial scan of a single browser upload, `folder` for a file package, and `public_url` for imports.

In Cloudflare, open **D1 SQL Database → checkskill-analytics → Console** to query the counters.

```sql
SELECT day_utc, input_type, source_url, count AS scans
FROM scan_counts_export
WHERE metric = 'scans'
ORDER BY day_utc DESC, input_type, source_url;
```

Use `metric = 'snyk_findings'` to see forecast counts by `snyk_code` and `severity`. The other metrics count returned CheckSkill findings, scans with at least one predicted Snyk issue, and scans that reached the finding limit. A missing metric row means no events of that type were recorded for that date, input type, and source URL.

To export the same counters, authenticate Wrangler for the Cloudflare account that owns the database and run:

```sh
npm run --silent analytics:export > checkskill-analytics.csv
```

The database schema lives in `d1/migrations`. Apply it before starting a local Worker with analytics or deploying a new database binding.
