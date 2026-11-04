# Elastic Security Automation

A read-only command-line starting point for understanding an Elastic deployment
before authoring detection rules. It discovers cluster resources and Kibana data
views, inspects mapped/runtime fields, and estimates document ingestion rates
from timestamped search buckets.

## Install

Python 3.10 or newer is required.

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e .
Copy-Item .env.example .env
```

Set `ESA_ELASTICSEARCH_URL` and `ESA_ELASTICSEARCH_API_KEY` in `.env`. Set
`ESA_KIBANA_URL` when using data-view commands. See [.env.example](.env.example)
for all supported settings.

Keep `ESA_VERIFY_CERTS=true` whenever possible. If you have intentionally
disabled certificate verification for a trusted development deployment and
want to hide urllib3's `InsecureRequestWarning`, set
`ESA_SUPPRESS_INSECURE_REQUEST_WARNINGS=true`. This only hides the warning; it
also suppresses Elasticsearch's `SecurityWarning` about disabled TLS
verification. This hides warnings; it does not enable certificate verification
or make the connection safer.

## Help

```powershell
esa --help
esa cluster --help
esa data-views --help
esa data-fields --help
esa fields --help
esa metrics --help
```

If the console script is not on `PATH`, run `python -m
elastic_security_automation --help` from the project directory.

## Commands

```powershell
# Cluster version, health, indices, data streams, and storage summary
esa cluster

# Kibana data views; optionally retrieve each view's field metadata
esa data-views --include-fields

# Security-focused field groups and sample values
esa data-fields
esa data-fields --data-view-id "my-view-id" --output-file

# Inspect Elasticsearch mappings and/or Kibana data-view fields
esa fields --index "logs-*"
esa fields --data-view-id "my-view-id"
esa fields --index "logs-*" --data-view-id "my-view-id"

# Cluster and index metrics plus document counts/rates over a time window
esa metrics --index "logs-*" --lookback 24h --interval 1h

# Save snapshots and latest summaries without changing the JSON stdout output
esa cluster --include-indices --include-data-streams --output-file
esa fields --index "logs-*" --output-file
esa data-views --include-fields --output-file
esa data-fields --output-file
esa metrics --index "logs-*" --lookback 24h --interval 1h --output-file

# Return concise results and replace the concise per-module summary
esa cluster --simple --output-file
esa data-views --simple --output-file
esa fields --index "logs-*" --simple --output-file
esa data-fields --simple --output-file
esa metrics --index "logs-*" --simple --output-file
```

## Development

```powershell
python -m pip install -e ".[dev]"
python -m pytest
```
