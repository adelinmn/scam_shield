"""Compare offline detector results against the official validation CSV."""

import argparse
import csv
from collections import Counter
from pathlib import Path

from scam_detector.cli import CSV_FIELDS, DEFAULT_OUTPUT, write_json
from scam_detector.model_assets import PROJECT_ROOT


EXPECTED = PROJECT_ROOT / "validation_expected_results.csv"
ACCEPTED_ALERT_WINDOWS = {"V11": range(3, 6)}
FIELDS = CSV_FIELDS[1:]


def read_results(path: Path) -> dict[str, dict]:
    with path.open(encoding="utf-8-sig", newline="") as stream:
        reader = csv.DictReader(stream)
        if reader.fieldnames != list(CSV_FIELDS):
            raise ValueError(f"Unexpected CSV columns in {path}")
        rows = {}
        for row in reader:
            if not row["id"] or row["id"] in rows:
                raise ValueError(f"Missing or duplicate id in {path}")
            if None in row or any(value is None for value in row.values()):
                raise ValueError(f"Invalid CSV row in {path}")
            rows[row["id"]] = {
                "verdict": row["verdict"],
                "scam_type": row["scam_type"],
                "risk_score": int(row["risk_score"]),
                "first_alert": int(row["first_alert"]) if row["first_alert"] else None,
                "red_flags": sorted(set(filter(None, row["red_flags"].split(";")))),
            }
        return rows


def compare(expected: dict[str, dict], actual: dict[str, dict]) -> dict:
    matches = Counter(dict.fromkeys(FIELDS, 0))
    exact_matches = 0
    scenarios = []
    for scenario_id, expected_row in sorted(expected.items()):
        actual_row = actual.get(scenario_id)
        differences = []
        window = ACCEPTED_ALERT_WINDOWS.get(scenario_id, ())
        for field in FIELDS:
            if actual_row is None:
                differences.append(field)
            elif expected_row[field] == actual_row[field] or (
                field == "first_alert" and actual_row[field] in window
            ):
                matches[field] += 1
            else:
                differences.append(field)
        exact_matches += not differences
        scenarios.append(
            {
                "id": scenario_id,
                "expected": expected_row,
                "actual": actual_row,
                "differences": differences,
                "accepted_alert_messages": list(window),
            }
        )
    return {
        "expected_count": len(expected),
        "actual_count": len(actual),
        "full_matches": exact_matches,
        "field_matches": dict(matches),
        "unexpected_ids": sorted(actual.keys() - expected.keys()),
        "scenarios": scenarios,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--results", type=Path, default=DEFAULT_OUTPUT / "results.csv")
    parser.add_argument("--expected", type=Path, default=EXPECTED)
    args = parser.parse_args()
    try:
        report = compare(read_results(args.expected), read_results(args.results))
        report_path = args.results.with_name("validation.json")
        if report_path.resolve() in {args.expected.resolve(), args.results.resolve()}:
            raise ValueError("The report path overlaps a validation input.")
        write_json(report_path, report)
    except (OSError, ValueError) as exc:
        parser.exit(2, f"Validation failed: {exc}\n")

    total = report["expected_count"]
    print(f"Full matches: {report['full_matches']}/{total}")
    for field, count in report["field_matches"].items():
        print(f"  {field}: {count}/{total}")
    for row in report["scenarios"]:
        if row["differences"]:
            detail = ", ".join(row["differences"]) if row["actual"] else "missing result"
            print(f"{row['id']}: {detail}")
    if report["unexpected_ids"]:
        print(f"Unexpected scenarios: {', '.join(report['unexpected_ids'])}")
    print(f"Details saved to {report_path}")
    return int(report["full_matches"] != total or bool(report["unexpected_ids"]))


if __name__ == "__main__":
    raise SystemExit(main())
