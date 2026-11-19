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

Run from the project root in Bash or Git Bash.

```sh
./test /input
./test ./validation_set
./test ./validation_set/V04.json --output ./example_outputs
```

`/input` can be a JSON scenario file or a directory containing scenarios. The
command scans subdirectories, reuses one model, and logs skipped input filenames
and the reason for each skip. It exits with status 1 when it processes zero
scenarios or encounters a setup or output error. With an unpacked source
archive, run `chmod +x test` in Bash if the file mode was lost.

In PowerShell, use the Windows Python launcher with the project virtual
environment active.

```powershell
py ./test ./validation_set
```

If `py` is unavailable, call the virtual environment's interpreter directly.

```powershell
.\.venv\Scripts\python.exe ./test ./validation_set
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

## Model and flag configuration

The default profile uses one Romanian hypothesis per flag and an uncalibrated
threshold of 0.75. You can copy the starter profile or use the following
partial profile to try alternative wording for one flag.
[`profiles/romanian_examples.json`](profiles/romanian_examples.json)

```json
{
  "hypotheses": {
    "RF_CODE_REQUEST": [
      "Expeditorul cere să i se trimită codul primit prin SMS.",
      "Expeditorul îi cere destinatarului să îi comunice un cod de autentificare."
    ]
  },
  "thresholds": {
    "RF_CODE_REQUEST": 0.75
  }
}
```

Each entry in a flag's array is paired with the message in a separate model
input. The model has a 512-token budget per pair. It preserves the hypothesis
and truncates the message if needed. The detector uses the highest score among
the alternatives and checks it against that flag's threshold. Keep each
sentence short and describe one concrete way the flag can appear. More
alternatives take more inference time and can increase false positives.

A profile replaces the hypothesis array for each flag it lists. Omitted flags
and thresholds inherit the defaults defined in the detector. Run the example
in a separate output folder.
[`scam_detector/flag_definitions.py`](scam_detector/flag_definitions.py)

```sh
python ./test ./validation_set --flag-profile ./profiles/romanian_examples.json --output ./outputs/romanian_examples
```

To load the same profile through the Python API, create one
`ScamDetector.from_flag_profile(Path("profiles/romanian_examples.json"))` and
reuse it across requests.

To override individual thresholds in a Python integration, create a detector
once at application startup and reuse it across requests.

```python
from scam_detector import ScamDetector
from scam_detector.model import FlagClassifier

detector = ScamDetector(FlagClassifier(), thresholds={"RF_CODE_REQUEST": 0.8})
```

`RF_SUSPICIOUS_CONTACT` is also a provisional model prediction. Confirming it
reliably requires official contact verification. The official point values and
verdict bands are fixed.

### Compare hypotheses and tune thresholds

Run the tuner on the 11 organizer-labeled cases with the baseline or a custom
profile. Run these Python commands through `./.venv/Scripts/python.exe` on
Windows if your environment is inactive.

```sh
python -m scripts.tune_flags --output ./outputs/flag_tuning/baseline
python -m scripts.tune_flags --profile ./profiles/romanian_examples.json
python ./test ./validation_set --flag-profile ./outputs/flag_tuning/official/profile.json --output ./outputs/tuned_examples
python -m scripts.validate --results ./outputs/tuned_examples/results.csv
```

`report.json` shows scenario-level precision, recall, F1, and false-positive
and false-negative IDs for each hypothesis and each pooled flag. The tuner
scores each sender message once and reuses those scores to select each
threshold by F1. It keeps the starting threshold unless a flag has at least
three positive and three negative labeled scenarios. The proposed
`profile.json` can be loaded with `--flag-profile`. The tuner measures flag
presence across the full scenario. Check verdicts and alert timing with the
separate detector run and validation command above.

The organizer set is useful for iteration. To measure generalization, use
separately reviewed development and holdout cases. The tuner accepts a CSV
with `id,split,annotator_reviewed,expected_red_flags`. Mark a row `YES` once
reviewed and give it semicolon-separated flag codes. Leave the flag cell empty
for a reviewed case with zero flags. Development is the default for these CSVs.
Pass `--input` with the scenario folder, `--labels` with the reviewed CSV, and
`--split holdout --profile PATH` to evaluate the frozen profile. Holdout mode
reports metrics without fitting thresholds. A dataset's ham, spam, or smishing
labels alone do not identify individual flags.

## Future rule integration

Subclass `RuleEngine` in [`scam_detector/rules.py`](scam_detector/rules.py) and
pass an instance as `ScamDetector(..., rules=engine)`. `evaluate(message, context)`
receives the original and normalized message text, extracted URLs and phone
numbers, sender metadata, channel, and earlier turns. The scaffold exposes the
path to `official_catalog.json` and returns `UNKNOWN` for every flag.
`FlagFusionEngine` uses the model threshold for `UNKNOWN`, activates
`CONFIRMED` flags, and suppresses `REJECTED` flags.

Future rule work includes official domain and phone checks, OTP requests versus
informational messages, sensitive data requests, payment and transfer requests,
remote access, deadlines and urgency, secrecy, new-number claims, and negations
that lead to false positives.

## Tests and validation

Run unit tests without downloading the model. To include real CPU inference
and repeatability tests, enable the integration tests after setup.

```sh
python -m unittest discover -s tests -v
SCAM_SHIELD_RUN_MODEL_TESTS=1 python -m unittest discover -s tests -v
./test ./validation_set
python -m scripts.validate
```

In PowerShell, set `$env:SCAM_SHIELD_RUN_MODEL_TESTS = '1'` before running the
integration tests. The validation command compares `outputs/results.csv`
against the official CSV, accepts alert messages 3–5 for V11, and writes
`outputs/validation.json` with the expected and observed values and all
field-level differences. It exits with status 1 when differences remain.

The CPU run with all thresholds at 0.75 processed 11 scenarios. It matched
2/11 complete results, 6/11 verdicts, 6/11 alert positions, 4/11 scam types,
2/11 scores and 2/11 red-flag sets.

| Scenario | Expected verdict / score / alert | Observed verdict / score / alert |
| --- | --- | --- |
| V01 | SCAM / 70 / 1 | SAFE / 0 / — |
| V02 | SCAM / 65 / 1 | SAFE / 0 / — |
| V03 | SAFE / 0 / — | SAFE / 0 / — |
| V04 | SCAM / 80 / 5 | SUSPICIOUS / 45 / 5 |
| V05 | SAFE / 0 / — | SAFE / 0 / — |
| V06 | SCAM / 85 / 1 | SAFE / 0 / — |
| V07 | SCAM / 95 / 1 | SCAM / 75 / 1 |
| V08 | SCAM / 70 / 3 | SCAM / 55 / 3 |
| V09 | SUSPICIOUS / 35 / 1 | SAFE / 0 / — |
| V10 | SCAM / 50 / 1 | SCAM / 60 / 1 |
| V11 | SCAM / 100 / 3–5 | SCAM / 90 / 1 |
