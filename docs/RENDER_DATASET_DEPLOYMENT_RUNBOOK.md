# Render database migration and URL dataset import runbook

This runbook applies migrations and imports the URL dataset into the intended Render PostgreSQL database. It is a separate production operation; the local verification performed in development does not authorize or perform any Render changes. Keep sandbox execution disabled throughout.

## 1. Confirm the target and take a backup

1. In the Render Dashboard, identify the exact PostgreSQL service used by the intended ScamShield backend. Record its service name, region, database name, and the backend service that references it. Confirm these with the service owner before running commands.
2. Check the database's **Recovery** page. For a durable pre-change backup, create and download a logical export, and record its timestamp and service identity. Render documents exports and point-in-time recovery in [Postgres Recovery and Backups](https://render.com/docs/postgresql-backups). On plans without dashboard exports, take a `pg_dump` from a trusted machine using the external connection string kept in a secure environment variable; never paste it into chat, logs, shell history, or this runbook.
3. Confirm the backup is complete and restorable, or confirm the available recovery option and window. Do not continue if there is no verified recovery path.
4. Open the **Shell** for the intended paid backend service (or a temporary/ephemeral shell based on that service's image). Render's [Shell and SSH documentation](https://render.com/docs/ssh) describes the available service shell types. Do not use a shell from a different service or environment.

## 2. Verify environment and migration state

From the backend working directory in the Render service, run a sanitized configuration check. It reports no URL, username, or password:

```sh
python - <<'PY'
from urllib.parse import urlsplit
from app.core.config import settings

parsed = urlsplit(settings.database_url.replace("postgresql+asyncpg://", "postgresql://", 1))
print("environment:", settings.environment)
print("database host:", parsed.hostname or "missing")
print("database port:", parsed.port or 5432)
print("database name:", parsed.path.lstrip("/"))
print("sandbox runtime enabled:", settings.sandbox_runtime_enabled)
print("sandbox network verified:", settings.sandbox_network_verified)
PY
```

Compare the reported host and database name privately with the intended database service in Render. Verify the environment is the intended deployment. Stop if the target is ambiguous, if the host is local, or if either sandbox flag is true; sandbox changes are outside this runbook.

Inspect the migration graph and database revision:

```sh
python -m alembic heads
python -m alembic current
python -m alembic history
```

The repository should have one migration head, `b7d03c81a942`. If there are multiple heads, a missing revision, an unexpected current revision, or a database/configuration discrepancy, stop and resolve it before deployment. Review pending migrations, including their effects on the target schema, before proceeding.

## 3. Stage and validate the dataset

Place `malicious_phish.csv` in the backend service's approved private artifact or storage mechanism. Do not commit the file, add it to a public URL, or print its records. In the backend directory, confirm the exact file exists and run the importer preview:

```sh
test -f data/urls/malicious_phish.csv
python -m scripts.import_url_dataset --dry-run
```

Expected source fingerprint:

```text
d83ce942075dd63ed4d11560cfdcd9d512caa3d680e292f22cab484e8f074d01
```

Expected totals for this reviewed source are 651,191 input rows, 636,666 accepted records, 10,327 duplicates, 8 ambiguous records excluded, and 4,190 malformed or unsupported records. Expected imported labels are 424,333 benign, 95,285 defacement, 23,635 malware, and 93,413 phishing. Stop if the fingerprint or counts differ; inspect the dataset version and importer output without printing raw rows.

## 4. Apply migrations and import

Only after backup, target, migration, and dataset checks pass, apply the reviewed pending migrations:

```sh
python -m alembic upgrade head
python -m alembic current
```

Confirm the current revision is `b7d03c81a942` before importing. Then run the actual importer:

```sh
python -m scripts.import_url_dataset data/urls/malicious_phish.csv
```

The importer replaces records for the same dataset name atomically. It stores canonical URL hashes, labels, and provenance in PostgreSQL; it does not store the raw source URL in that index.

## 5. Verify the production result

Use the application shell for a read-only database verification. This prints only counts, labels, indexes, and provenance consistency:

```sh
python - <<'PY'
import asyncio
from sqlalchemy import text
from app.db.session import engine

async def main():
    async with engine.connect() as connection:
        total = await connection.scalar(text(
            "select count(*) from url_dataset_records where dataset_name = :name"
        ), {"name": "malicious_phish.csv"})
        labels = (await connection.execute(text(
            "select source_label, count(*) from url_dataset_records "
            "where dataset_name = :name group by source_label order by source_label"
        ), {"name": "malicious_phish.csv"})).all()
        provenance = (await connection.execute(text(
            "select count(distinct dataset_fingerprint), min(dataset_fingerprint), "
            "max(dataset_fingerprint), count(distinct imported_at) "
            "from url_dataset_records where dataset_name = :name"
        ), {"name": "malicious_phish.csv"})).one()
        indexes = (await connection.execute(text(
            "select indexname from pg_indexes where tablename = 'url_dataset_records' order by indexname"
        ))).scalars().all()
    print("total:", total)
    print("labels:", dict(labels))
    print("fingerprint count/min/max and import-time count:", provenance)
    print("indexes:", indexes)
    await engine.dispose()

asyncio.run(main())
PY
```

Confirm the count is `636666`, label totals match the expected values above, fingerprint count is `1`, the minimum and maximum fingerprints equal the expected SHA-256 value, import-time count is `1`, and all expected indexes appear.

Then verify behavior using the application's authenticated URL decision endpoint and controlled known records, without echoing request URLs into logs:

- `url_dataset_records` contains 636,666 records for `malicious_phish.csv`.
- Label counts equal the expected counts above; the eight ambiguous keys are absent.
- The primary-key index exists on `canonical_hash`; the dataset and label indexes exist.
- An exact phishing source record returns `known_malicious` with dataset name, fingerprint, label, and import time.
- An exact benign source record returns `non_malicious_label`, never a safe verdict.
- A unique, unrelated path on a source hostname returns `not_listed`; matching is not by domain alone.
- An unmatched URL with sandbox disabled returns `runtime_unavailable` / `unverified`, not safe. A failed lookup must return no verdict rather than fall through as a dataset miss.

Do not print or log submitted URLs, dataset URLs, credentials, or full database URLs while verifying. Keep `SANDBOX_RUNTIME_ENABLED=false` and `SANDBOX_NETWORK_VERIFIED=false`; this dataset deployment does not demonstrate a restricted disposable-browser network.

## Recovery notes

The importer replacement is transactional. If it fails before commit, the previous rows for this dataset name remain. For a bad migration or other schema/data problem, stop writes and use the previously verified Render recovery plan; do not improvise destructive downgrade or restore commands on the production database. Render documents logical exports and point-in-time recovery in [its backup documentation](https://render.com/docs/postgresql-backups).
