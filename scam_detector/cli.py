"""Run the offline detector over a JSON file or directory."""

import argparse
import csv
import hashlib
import json
import os
import re
import sys
from collections.abc import Callable
from contextlib import contextmanager
from pathlib import Path, PureWindowsPath
from tempfile import NamedTemporaryFile

from filelock import FileLock, Timeout

from .conversation import ScenarioError, parse_scenario
from .detector import ScamDetector, analyze_scenario
from .model import ModelSetupError
from .model_assets import PROJECT_ROOT


DEFAULT_OUTPUT = PROJECT_ROOT / "outputs"
CSV_FIELDS = ("id", "verdict", "scam_type", "risk_score", "first_alert", "red_flags")
SUMMARY_FIELDS = ("total_scenarios", "scam", "suspicious", "safe")
_PORTABLE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,79}")


def result_filename(scenario_id: str) -> str:
    if _PORTABLE_ID.fullmatch(scenario_id) and not PureWindowsPath(scenario_id).is_reserved():
        return f"{scenario_id}.json"
    digest = hashlib.sha256(scenario_id.encode("utf-8")).hexdigest()
    return f"~{digest}.json"


@contextmanager
def atomic_text(path: Path):
    """Write a sibling temporary file before replacing the destination."""
    with NamedTemporaryFile(
        dir=path.parent, encoding="utf-8", newline="", mode="w", delete=False
    ) as stream:
        temporary = Path(stream.name)
        try:
            yield stream
            stream.close()
            temporary.replace(path)
        finally:
            stream.close()
            temporary.unlink(missing_ok=True)


def write_json(path: Path, value) -> None:
    with atomic_text(path) as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2)
        stream.write("\n")


def scenario_files(path: Path, output: Path) -> list[Path]:
    if path.is_file():
        if path.suffix.lower() != ".json":
            raise ValueError("The input file must have a .json extension.")
        if path.is_relative_to(output / "scenarios"):
            raise ValueError("The input file is inside the generated scenarios directory.")
        return [path]
    if path.is_dir():
        if path.is_relative_to(output / "scenarios"):
            raise ValueError("The input directory is inside the generated scenarios directory.")
        return sorted(
            file
            for file in path.rglob("*")
            if file.suffix.lower() == ".json"
            and not file.is_relative_to(output / "scenarios")
            and file.is_file()
            and not file.is_symlink()
            and file not in {output / "summary.json", output / "validation.json"}
        )
    raise FileNotFoundError(f"Input does not exist: {path}")


def read_scenario_json(path: Path):
    try:
        return json.loads(path.read_text(encoding="utf-8-sig"))
    except json.JSONDecodeError as exc:
        raise ScenarioError(f"Invalid JSON at line {exc.lineno}, column {exc.colno}.") from exc
    except UnicodeError as exc:
        raise ScenarioError("Input contains invalid UTF-8.") from exc
    except RecursionError as exc:
        raise ScenarioError("JSON input is nested too deeply.") from exc
    except ValueError as exc:
        raise ScenarioError("JSON contains an unsupported value.") from exc


def is_generated_result(path: Path) -> bool:
    if path.is_symlink() or not path.is_file():
        return False
    try:
        result = json.loads(path.read_text(encoding="utf-8"))
        return (
            isinstance(result, dict)
            and isinstance(result.get("id"), str)
            and "message_results" in result
            and "rule_evidence" in result
            and os.path.normcase(result_filename(result["id"])) == os.path.normcase(path.name)
        )
    except (OSError, ValueError, RecursionError):
        return False


def is_generated_summary(path: Path) -> bool:
    try:
        summary = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, RecursionError):
        return False
    return (
        isinstance(summary, dict)
        and summary.keys() == set(SUMMARY_FIELDS)
        and all(type(count) is int for count in summary.values())
    )


def is_generated_csv(path: Path) -> bool:
    try:
        with path.open(encoding="utf-8", newline="") as stream:
            return next(csv.reader(stream), []) == list(CSV_FIELDS)
    except (OSError, ValueError, csv.Error):
        return False


def check_destination(path: Path, is_generated: Callable[[Path], bool]) -> None:
    if path.is_symlink() or (path.exists() and not is_generated(path)):
        raise ValueError(f"Existing file conflicts with a generated result at {path}")


def write_outputs(output: Path, results: list[dict], summary: dict) -> None:
    output.mkdir(parents=True, exist_ok=True)
    lock_path = output / ".write.lock"
    if lock_path.is_symlink():
        raise ValueError("The output lock cannot be a redirected path.")
    with FileLock(lock_path, timeout=30):
        scenarios = output / "scenarios"
        if scenarios.resolve() != scenarios:
            raise ValueError("The generated scenarios directory cannot be a redirected path.")
        results_path = output / "results.csv"
        summary_path = output / "summary.json"
        check_destination(results_path, is_generated_csv)
        check_destination(summary_path, is_generated_summary)
        scenarios.mkdir(exist_ok=True)
        current = {result_filename(result["id"]): result for result in results}
        for name in current:
            check_destination(scenarios / name, is_generated_result)
        for name, result in current.items():
            write_json(scenarios / name, result)
        current_names = {os.path.normcase(name) for name in current}
        for old_file in scenarios.glob("*.json"):
            if os.path.normcase(old_file.name) not in current_names and is_generated_result(old_file):
                old_file.unlink()

        with atomic_text(results_path) as stream:
            writer = csv.DictWriter(stream, fieldnames=CSV_FIELDS)
            writer.writeheader()
            for result in results:
                row = {field: result[field] for field in CSV_FIELDS}
                row["red_flags"] = ";".join(row["red_flags"])
                writer.writerow(row)
        write_json(summary_path, summary)


def run_batch(
    input_path: Path,
    output_path: Path = DEFAULT_OUTPUT,
    analyze: Callable[[dict], dict] = analyze_scenario,
    *,
    flag_profile: Path | None = None,
) -> tuple[dict, int]:
    input_path, output_path = input_path.resolve(), output_path.resolve()
    files = scenario_files(input_path, output_path)
    results = []
    detector = None
    filenames = set()
    skipped = 0
    for file in files:
        try:
            scenario = read_scenario_json(file)
            if isinstance(scenario, dict) and isinstance(scenario.get("id"), str):
                name = result_filename(scenario["id"]).casefold()
                if name in filenames:
                    raise ScenarioError("Duplicate scenario id or result filename.")
            if flag_profile is None:
                result = analyze(scenario)
            else:
                conversation = parse_scenario(scenario)
        except UnicodeError:
            reason = "Input contains invalid Unicode text."
        except (OSError, ScenarioError) as exc:
            reason = str(exc)
        else:
            if flag_profile is not None:
                if detector is None:
                    detector = ScamDetector.from_flag_profile(flag_profile)
                result = detector.analyze_conversation(conversation)
            results.append(result)
            filenames.add(result_filename(result["id"]).casefold())
            continue
        print(f"Skipped {file.name}: {reason}", file=sys.stderr)
        skipped += 1

    results.sort(key=lambda result: result["id"])
    summary = dict.fromkeys(SUMMARY_FIELDS, 0)
    for result in results:
        summary[result["verdict"].lower()] += 1
    summary["total_scenarios"] = len(results)
    write_outputs(output_path, results, summary)
    return summary, skipped


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path, help="JSON scenario file or directory")
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT, help="result directory")
    parser.add_argument("--flag-profile", type=Path, help="JSON hypotheses and thresholds")
    args = parser.parse_args(argv)
    try:
        summary, skipped = run_batch(args.input, args.output, flag_profile=args.flag_profile)
    except (OSError, ValueError, ModelSetupError, Timeout) as exc:
        print(f"Scam Shield: {exc}", file=sys.stderr)
        return 1

    print("Scam Shield - Offline Detector")
    print(f"\nInput: {args.input}")
    print(f"Scenarios processed: {summary['total_scenarios']}")
    if skipped:
        print(f"Files skipped: {skipped}")
    for verdict in ("scam", "suspicious", "safe"):
        print(f"{verdict.upper():12} {summary[verdict]}")
    print("\nResults saved to")
    for filename in ("results.csv", "summary.json", "scenarios"):
        print(f"  {args.output / filename}")
    return 0 if summary["total_scenarios"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
