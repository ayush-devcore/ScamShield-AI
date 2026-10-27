import csv
import re
from collections import Counter
from pathlib import Path
from urllib.parse import urlsplit

BASE = Path(__file__).resolve().parents[1]
SOURCE = BASE / "data" / "urls" / "malicious_phish.csv"
OUTPUT = BASE / "data" / "urls" / "cleaned_urls.csv"

SCHEME_PATTERN = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*://")

def get_columns(fieldnames):
    columns = {name.strip().lower(): name for name in fieldnames if name}
    if "url" not in columns or "type" not in columns:
        raise ValueError(f"Expected url,type columns; found {fieldnames}")
    return columns["url"], columns["type"]

def get_host_group(url):
    candidate = url.strip()
    if not SCHEME_PATTERN.match(candidate) and not candidate.startswith("//"):
        candidate = "//" + candidate.lstrip("/")

    try:
        host = urlsplit(candidate).hostname
        if host:
            return host.lower().rstrip(".")
    except ValueError:
        pass

    # Keep unparseable URLs grouped by exact string, without visiting them.
    return "unparsed:" + url

def main():
    if not SOURCE.is_file():
        raise FileNotFoundError(f"Dataset not found: {SOURCE}")

    labels_by_url = {}
    conflicting_urls = set()
    total_rows = 0

    with SOURCE.open("r", encoding="utf-8-sig", errors="replace", newline="") as f:
        reader = csv.DictReader(f)
        url_column, label_column = get_columns(reader.fieldnames or [])

        for row in reader:
            total_rows += 1
            url = (row.get(url_column) or "").strip()
            label = (row.get(label_column) or "").strip().lower()

            if not url or not label:
                continue

            previous = labels_by_url.get(url)
            if previous is not None and previous != label:
                conflicting_urls.add(url)
            else:
                labels_by_url.setdefault(url, label)

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    label_counts = Counter()
    host_groups = set()
    written_urls = set()
    removed_conflicts = 0
    removed_duplicates = 0

    with SOURCE.open("r", encoding="utf-8-sig", errors="replace", newline="") as src, \
         OUTPUT.open("w", encoding="utf-8", newline="") as dst:

        reader = csv.DictReader(src)
        url_column, label_column = get_columns(reader.fieldnames or [])
        writer = csv.DictWriter(
            dst,
            fieldnames=["url", "type", "host_group"],
        )
        writer.writeheader()

        for row in reader:
            url = (row.get(url_column) or "").strip()
            label = (row.get(label_column) or "").strip().lower()

            if not url or not label:
                continue

            if url in conflicting_urls:
                removed_conflicts += 1
                continue

            if url in written_urls:
                removed_duplicates += 1
                continue

            written_urls.add(url)
            group = get_host_group(url)
            host_groups.add(group)

            writer.writerow({
                "url": url,
                "type": label,
                "host_group": group,
            })
            label_counts[label] += 1

    print("\n=== CLEAN DATASET SUMMARY ===")
    print(f"Original rows: {total_rows:,}")
    print(f"Conflicting URL strings excluded: {len(conflicting_urls):,}")
    print(f"Rows excluded due to conflicting labels: {removed_conflicts:,}")
    print(f"Duplicate rows excluded: {removed_duplicates:,}")
    print(f"Clean rows written: {sum(label_counts.values()):,}")
    print(f"Unique host groups: {len(host_groups):,}")
    print(f"Output: {OUTPUT}")
    print("\nClass distribution:")
    for label, count in label_counts.most_common():
        print(f"  {label}: {count:,} ({count / max(sum(label_counts.values()), 1) * 100:.2f}%)")
    print("\nNo URLs were visited.")

if __name__ == "__main__":
    main()
