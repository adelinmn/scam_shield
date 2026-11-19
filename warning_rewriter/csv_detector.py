"""
Stand-in detector that reads the OFFICIAL answer key instead of analysing text.
Use it to test the whole pipeline (scoring, first_alert, warnings, LLM polish) before your
MiniLM detector exists. It only works for the 11 validation scenarios: it looks the
scenario up by its "id" and raises a clear error for anything else (e.g. the secret Test Set).

Behaviour per message prefix:
  * before the scenario's first_alert -> no flags (so the alert fires exactly at first_alert)
  * from first_alert on               -> all red flags + scam type from the CSV
Caveat: because the CSV has no per-message timing, the first warning already contains all
final flags (e.g. V04's message-5 warning mentions secrecy that only appears in message 6).

Paths: the CSV is looked up one directory above these scripts first
(../validation_expected_results.csv), then next to them / in the current folder's parent.
"""
from __future__ import annotations

import csv
import re
from pathlib import Path

from scam_warnings import Conversation

HERE = Path(__file__).resolve().parent
CSV_NAME = "validation_expected_results.csv"


def _first_existing(candidates, what):
    for c in candidates:
        if Path(c).exists():
            return Path(c)
    raise FileNotFoundError(f"Could not find {what}. Looked in: " + ", ".join(str(c) for c in candidates))


def default_csv_path() -> Path:
    return _first_existing([HERE.parent / CSV_NAME, Path.cwd().parent / CSV_NAME, HERE / CSV_NAME], CSV_NAME)


def default_validation_dir() -> Path:
    return _first_existing([HERE.parent / "validation_set", HERE / "validation_set",
                            Path.cwd().parent / "validation_set", Path.cwd() / "validation_set"], "validation_set/")


def resolve_conversation_path(arg: str) -> Path:
    """'V04', 'V04.json' or a real path -> path of the JSON file."""
    if Path(arg).exists():
        return Path(arg)
    name = arg if arg.endswith(".json") else arg + ".json"
    return default_validation_dir() / name


def _first(v: str):
    """'5' -> 5 ; a window like '5-7' -> its first message (5) ; '' -> None."""
    v = (v or "").strip()
    if not v:
        return None
    m = re.match(r"^(\d+)", v)
    return int(m.group(1)) if m else None


class CsvDetector:
    def __init__(self, csv_path=None):
        self.rows = {}
        with open(csv_path or default_csv_path(), encoding="utf-8-sig", newline="") as fh:
            for r in csv.DictReader(fh):
                self.rows[r["id"]] = {
                    "scam_type": r["scam_type"] or "NONE",
                    "first_alert": _first(r["first_alert"]),
                    "flags": set(filter(None, r["red_flags"].split(";"))),
                }

    def __call__(self, conv: Conversation):
        row = self.rows.get(conv.id)
        if row is None:
            raise KeyError(f"Scenario id {conv.id!r} is not in the answer-key CSV. The CSV detector only "
                           f"covers V01-V11; use your real detector for anything else.")
        if row["first_alert"] is None or len(conv.messages) < row["first_alert"]:
            return set(), "NONE"
        return set(row["flags"]), row["scam_type"]
