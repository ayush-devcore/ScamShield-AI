import argparse
import csv
from collections import Counter, defaultdict
from pathlib import Path
import re
import sys

def main():
    parser = argparse.ArgumentParser(description="Audit a labeled URL CSV without visiting URLs.")
    parser.add_argument(
        "--input",
        default=r"data\urls\malicious_phish.csv",
        help="Path to the CSV dataset",
    )
    args = parser.parse_args()
    path = Path(args.input)

    if not path.is_file():
        print(f"ERROR: Dataset not found: {path.resolve()}")
        return 1

    total_rows = 0
    missing_urls = 0
    missing_labels = 0
    scheme_count = 0
    duplicate_rows = 0
    labels = Counter()
    seen_urls = set()
    labels_by_url = defaultdict(set)

    scheme_pattern = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*://")

    with path.open("r", encoding="utf-8-sig", errors="replace", newline="") as handle:
        reader = csv.DictReader(handle)

        if not reader.fieldnames:
            print("ERROR: CSV has no header.")
            return 1

        columns = {name.strip().lower(): name for name in reader.fieldnames if name}
        if "url" not in columns or "type" not in columns:
            print(f"ERROR: Expected columns 'url' and 'type'; found {reader.fieldnames}")
            return 1

        url_column = columns["url"]
        label_column = columns["type"]

        for row in reader:
            total_rows += 1
            url = (row.get(url_column) or "").strip()
            label = (row.get(label_column) or "").strip().lower()

            if not url:
                missing_urls += 1
                continue

            if not label:
                missing_labels += 1
            else:
                labels[label] += 1
                labels_by_url[url].add(label)

            if scheme_pattern.match(url):
                scheme_count += 1

            if url in seen_urls:
                duplicate_rows += 1
            else:
                seen_urls.add(url)

    conflicting_urls = sum(
        1 for assigned_labels in labels_by_url.values()
        if len(assigned_labels) > 1
    )

    print("\n=== SCAMSHIELD URL DATASET AUDIT ===")
    print(f"File: {path.resolve()}")
    print(f"Total data rows: {total_rows:,}")
    print(f"Unique non-empty URL strings: {len(seen_urls):,}")
    print(f"Duplicate rows after first occurrence: {duplicate_rows:,}")
    print(f"Rows with missing URLs: {missing_urls:,}")
    print(f"Rows with missing labels: {missing_labels:,}")
    print(f"Unique URLs with conflicting labels: {conflicting_urls:,}")
    print(f"URLs with explicit scheme: {scheme_count:,}")
    print(f"URLs without explicit scheme: {len(seen_urls) - len(set()):,}" if False else
          f"Rows without explicit scheme: {total_rows - missing_urls - scheme_count:,}")

    print("\nLabel distribution:")
    for label, count in labels.most_common():
        print(f"  {label}: {count:,} ({count / max(total_rows, 1) * 100:.2f}%)")

    print("\nAudit complete. No URLs were visited.")
    return 0

if __name__ == "__main__":
    sys.exit(main())
