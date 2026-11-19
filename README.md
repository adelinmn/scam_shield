# Scam Shield offline detector

Scam Shield analyzes Romanian messages and conversations with a local multilingual
NLI model. The Python API and batch command report red flags, the cumulative risk
score, the first alert, and the likely scam category.

## One-time setup

Use Python 3.11 or 3.12. Create a virtual environment and activate it before
installing dependencies.

```sh
python -m venv .venv
source .venv/bin/activate
```

In Git Bash on Windows, activate with `source .venv/Scripts/activate`. In
PowerShell, use `./.venv/Scripts/Activate.ps1` or invoke
`./.venv/Scripts/python.exe` directly in the Python commands below.

```sh
python -m pip install -r requirements.txt
python -m scripts.download_model
```

For CPU-only PyTorch on Linux, you can install the smaller CPU build before
installing the requirements.

```sh
python -m pip install torch==2.8.0 --index-url https://download.pytorch.org/whl/cpu
```

Setup downloads about 450 MB from
[the pinned multilingual MiniLM checkpoint](https://huggingface.co/MoritzLaurer/multilingual-MiniLMv2-L6-mnli-xnli/tree/0a71e92a985b6e1ad1828cf67ce9c459639c1dca)
into `models/multilingual-MiniLMv2-L6-mnli-xnli/`. Once setup finishes, you can
disconnect. Inference loads the tokenizer and safetensors weights from disk in
local-only mode. Missing or unreadable model files produce a setup error.

CPU is the default. To select a CUDA GPU, install a compatible CUDA build of
PyTorch 2.8.0 and set `SCAM_SHIELD_DEVICE=cuda:0` before the first analysis.
Set `SCAM_SHIELD_MODEL_DIR` before setup and inference to use a different local
model directory. The setup command also accepts `--model-dir`.

## Batch command

Run `test.py` from the project root with an input path.

```sh
python test.py /input
python test.py ./validation_set
python test.py ./validation_set/V04.json --output ./example_outputs
```

`/input` can be a JSON scenario file or a directory containing scenarios. The
command scans subdirectories, reuses one model, and prints each scenario's
result as it finishes. It logs skipped input filenames and the reason for
each skip. It exits with status 1 when it processes zero scenarios or
encounters a setup or output error.

In PowerShell, use the Windows Python launcher with the project virtual
environment active.

```powershell
py test.py ./validation_set
```

If `py` is unavailable, call the virtual environment's interpreter directly.

```powershell
.\.venv\Scripts\python.exe test.py ./validation_set
```

The default destination is the project’s `outputs/` directory.

| File | Contents |
| --- | --- |
| `scenarios/<id>.json` | Full result for each processed scenario |
| `results.csv` | Rows sorted by scenario ID with semicolon-delimited red flags |
| `summary.json` | Processed, scam, suspicious and safe counts |

Each run refreshes those outputs and removes stale generated scenario files.
IDs that are unsafe as cross-platform filenames use a stable hashed filename.
The original ID remains in the JSON and CSV. Generated output and model weights
are ignored by Git.

## Python API

```python
import json
from pathlib import Path

from scam_detector import analyze_scenario

scenario = json.loads(Path("validation_set/V04.json").read_text(encoding="utf-8"))
result = analyze_scenario(scenario)
print(result["verdict"], result["risk_score"], result["first_alert"])
```

Use the official JSON shape with `id`, `channel`, `sender` and `messages`.
Messages contain `n`, `from` (`sender` or `reader`) and `text`. Message numbers
determine chronological order. Sender turns contribute flag evidence. Reader
replies retain their message numbers and appear in the scam-type context and in
the preceding conversation passed to the rules interface.

Each flag contributes its official points once, capped at 100. Scores of 0–24
are `SAFE`, 25–49 are `SUSPICIOUS`, and 50–100 are `SCAM`. `first_alert` is the
first message number with a cumulative score of at least 25, or `null` if there
was no alert. `flag_messages` records the first turn for each detected flag.

`model_scores` contains the maximum model score for each flag over the sender
turns. `message_results` contains all 13 raw flag scores, active flags, and the
cumulative risk at each sender turn. `rule_evidence` contains each rule status
by message number. `scam_type_scores` contains the type-stage scores for
`SUSPICIOUS` and `SCAM` scenarios. `SAFE` scenarios return type `NONE`. Original
messages, phone numbers and links are omitted from generated results.

## Flag wording and thresholds

Edit `phrases` and `threshold` for any flag in the detector's configuration
file. Each flag has Romanian hypotheses and its own threshold.
[`scam_detector/flag_config.json`](scam_detector/flag_config.json)

```json
{
  "RF_CODE_REQUEST": {
    "phrases": [
      "Expeditorul cere să i se trimită codul primit prin SMS.",
      "Expeditorul îi cere destinatarului să îi comunice un cod de autentificare."
    ],
    "threshold": 0.75
  }
}
```

Each phrase gets its own model input with the message. The default aggregation is
`max`. You can set an optional `aggregation` per flag to `max`, `mean`, `top2`, or
`top3`. Top-N uses the mean of up to N phrases. The aggregate is compared against
the flag's threshold. Keep phrases short and use a threshold from 0 to 1.
Restart a running Python application to load the new settings.

For `RF_SUSPICIOUS_CONTACT`, the rules check declared organization details against
`official_catalog.json`. They compare the exact hostname, including permitted
subdomains, and the normalized sender or advertised callback number. An explicit
affiliation can carry forward to later sender messages in the same conversation.
The official point values and verdict bands are fixed.

Edit the array of phrases for each scam type. An entry can be an array directly
or an object containing a `phrases` array. Each phrase is scored separately.
For a suspicious or scam result, the selector ranks compatible types with strong
behavioral evidence first. `OTHER` is the fallback. A safe result uses `NONE`.
Restart the detector after editing the config.
[`scam_detector/scam_type_config.json`](scam_detector/scam_type_config.json)

## Rules and detector modes

Subclass `RuleEngine` in [`scam_detector/rules.py`](scam_detector/rules.py) and
pass an instance as `ScamDetector(..., rules=engine)`. `evaluate(message, context)`
receives the original and normalized message text, extracted URLs and phone
numbers, sender metadata, channel, and earlier turns.
`FlagFusionEngine` uses the model threshold for `UNKNOWN`, activates
`CONFIRMED` flags, and suppresses `REJECTED` flags.

`scam_type_rule_evidence` contains the evidence strength, reasons and matched
terms. The selector uses the model to rank ties between strongly supported types.
When rules supply no strong candidate, the selector considers compatible types
with a model score of at least 0.75 and gives weak rule support a 0.025 bonus.
`scam_type_scores` contains raw model ranking scores.

`context_flags` and `context_flag_messages` expose informational signals such as
`INFO_BANK_CONTEXT` and `INFO_OTP_NOTICE`. They appear in the terminal and the full
scenario JSON and contribute zero points. The CSV `red_flags` column contains
the flags used by the official score.

```sh
python test.py ./validation_set --mode hybrid
python test.py ./validation_set --mode model-only
python test.py ./validation_set --mode rules-only
python test.py ./validation_set/V04.json --debug --output ./outputs/debug
```

The default mode is `hybrid`. `rules-only` can run without model weights.
With `--debug`, each scenario JSON includes per-turn thresholds, hypothesis
scores in configuration order, rule reasons, overrides and the type
selection. The diagnostic output omits raw message text.

## Tests and validation

Run unit tests without downloading the model. To include real CPU inference
and repeatability tests, enable the integration tests after setup.

```sh
python -m unittest discover -s tests -v
SCAM_SHIELD_RUN_MODEL_TESTS=1 python -m unittest discover -s tests -v
python test.py ./validation_set
python -m scripts.validate
python -m scripts.compare_modes
```

In PowerShell, set `$env:SCAM_SHIELD_RUN_MODEL_TESTS = '1'` before running the
integration tests. The validation command compares `outputs/results.csv`
against the official CSV, accepts alert messages 3–5 for V11, and writes
`outputs/validation.json` with the expected and observed values and all
field-level differences. It exits with status 1 when differences remain.

The comparison command evaluates all three modes on the 11 validation cases
and 100 additional cases. It writes the results, per-flag precision, recall
and F1, false positives on `SAFE` cases, and cases that improved or
regressed to `outputs/rule_comparison/comparison.json`.

## Accuracy audit and threshold trials

Use a dedicated output directory for each batch. The evaluator checks exact
scenario ID coverage and reports verdict, scam type, risk score, first alert,
exact red-flag sets, and per-class precision, recall and F1.

```sh
python test.py ./testing_set2/input --output ./outputs/audit_improved
python -m scripts.evaluate ./testing_set2/validation_expected_results.csv ./outputs/audit_improved/results.csv --output ./outputs/audit/comparison.json
python -m scripts.score_cache ./testing_set2/input ./outputs/audit/scores.json
python -m scripts.tune_flags ./testing_set2/input ./testing_set2/validation_expected_results.csv ./outputs/audit/scores.json ./outputs/audit/trials.json
```

The cache stores each hypothesis score alongside the source JSON hash. Regenerate
it after changing the inputs, hypotheses, or model weights. The tuning command
compares aggregation methods, rules-only and model-only ablations. It groups
related scenarios before making three folds and tests each fold using thresholds
fitted on the other two. It saves the thresholds and metrics for each trial.
Set `--minimum`, `--maximum`, and `--step` to change the search range or
`--baseline-config` to repeat a trial with older thresholds and the same phrases.
See [the audit](AUDIT.md) for this version's evaluation and limitations.
