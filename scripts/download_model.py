"""Download only the pinned model assets needed for offline inference."""

import argparse
import os
from pathlib import Path

from scam_detector.model_assets import DEFAULT_MODEL_DIR, MODEL_FILES, MODEL_ID, MODEL_REVISION


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--model-dir",
        type=Path,
        default=os.environ.get("SCAM_SHIELD_MODEL_DIR") or DEFAULT_MODEL_DIR,
    )
    args = parser.parse_args()
    try:
        from huggingface_hub import snapshot_download
    except ImportError:
        parser.exit(1, "Install the dependencies with python -m pip install -r requirements.txt.\n")

    try:
        directory = snapshot_download(
            repo_id=MODEL_ID,
            revision=MODEL_REVISION,
            allow_patterns=MODEL_FILES,
            local_dir=args.model_dir,
            token=False,
        )
    except Exception as exc:
        parser.exit(1, f"Model download failed: {exc}\n")
    missing = [name for name in MODEL_FILES if not (Path(directory) / name).is_file()]
    if missing:
        parser.exit(1, f"Model download is incomplete: {', '.join(missing)}\n")
    print(f"Offline model ready at {directory}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
