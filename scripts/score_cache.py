"""Save offline NLI scores by scenario, turn, flag and hypothesis index."""

import argparse
import hashlib
import json
from functools import lru_cache
from pathlib import Path
from time import perf_counter

from scam_detector.cli import DEFAULT_OUTPUT, scenario_files, write_json
from scam_detector.conversation import parse_scenario
from scam_detector.flag_definitions import load_flag_config
from scam_detector.model import FlagClassifier
from scam_detector.scam_types import load_scam_type_hypotheses, type_premise


def load_case(path: Path):
    raw = path.read_bytes()
    return parse_scenario(json.loads(raw.decode("utf-8-sig"))), hashlib.sha256(raw).hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()

    inputs = scenario_files(args.input.resolve(), DEFAULT_OUTPUT)
    if args.output.resolve() in inputs or args.output.resolve().is_relative_to(args.input.resolve()):
        parser.error("Save the score cache outside the input scenarios")
    model = FlagClassifier()
    flag_phrases = {code: list(config.phrases) for code, config in load_flag_config().items()}
    type_phrases = {code: list(phrases) for code, phrases in load_scam_type_hypotheses().items()}
    started = perf_counter()

    @lru_cache(maxsize=1024)
    def score_flags(text: str):
        return model.score_phrase_groups([text], flag_phrases)[0]

    cases = {}
    for index, path in enumerate(inputs, 1):
        scenario, digest = load_case(path)
        if scenario.id in cases:
            raise ValueError(f"Duplicate scenario ID: {scenario.id}")
        cases[scenario.id] = {
            "input_sha256": digest,
            "turns": {
                str(turn.number): score_flags(turn.text)
                for turn in scenario.messages if turn.role == "sender"
            },
            "scam_types": model.score_phrase_groups([type_premise(scenario)], type_phrases)[0],
        }
        if index % 25 == 0 or index == len(inputs):
            print(f"Scored {index}/{len(inputs)} in {perf_counter() - started:.1f}s", flush=True)

    args.output.parent.mkdir(parents=True, exist_ok=True)
    write_json(args.output, {
        "format": 1, "flag_phrases": flag_phrases, "type_phrases": type_phrases, "cases": cases,
    })


if __name__ == "__main__":
    main()
