"""Independent multilingual zero-shot NLI scores from local model files."""

import os
from collections.abc import Mapping, Sequence
from pathlib import Path
from threading import Lock

from .flag_profiles import resolve_hypotheses
from .model_assets import DEFAULT_MODEL_DIR, MODEL_FILES


class ModelSetupError(RuntimeError):
    """The local inference environment needs to be set up or repaired."""


class FlagClassifier:
    def __init__(
        self,
        model_dir: str | Path | None = None,
        device: str | None = None,
        batch_size: int = 16,
        *,
        flag_hypotheses: Mapping[str, Sequence[str]] | None = None,
    ) -> None:
        hypotheses = resolve_hypotheses(flag_hypotheses)
        model_dir = Path(
            model_dir or os.environ.get("SCAM_SHIELD_MODEL_DIR") or DEFAULT_MODEL_DIR
        ).resolve()
        missing = [name for name in MODEL_FILES if not (model_dir / name).is_file()]
        if missing:
            raise ModelSetupError(
                f"Missing model files in {model_dir}: {', '.join(missing)}. "
                "Run python -m scripts.download_model during setup."
            )
        if batch_size < 1:
            raise ValueError("batch_size must be positive.")
        device = device or os.environ.get("SCAM_SHIELD_DEVICE") or "cpu"
        if device.split(":", 1)[0] not in {"cpu", "cuda"}:
            raise ModelSetupError("Choose cpu, cuda or a CUDA device such as cuda:0.")
        if device.startswith("cuda"):
            os.environ.setdefault("CUBLAS_WORKSPACE_CONFIG", ":4096:8")

        try:
            import torch
            from transformers import AutoModelForSequenceClassification, AutoTokenizer
        except ImportError as exc:
            raise ModelSetupError(
                "Install inference dependencies with python -m pip install -r requirements.txt."
            ) from exc

        self._torch = torch
        self._batch_size = batch_size
        self._inference_lock = Lock()
        try:
            self._device = torch.device(device)
            if self._device.type == "cuda" and not torch.cuda.is_available():
                raise ModelSetupError("CUDA is unavailable. Choose cpu or install CUDA PyTorch.")
            self._tokenizer = AutoTokenizer.from_pretrained(
                model_dir, local_files_only=True, trust_remote_code=False, use_fast=True
            )
            self._model = AutoModelForSequenceClassification.from_pretrained(
                model_dir,
                local_files_only=True,
                trust_remote_code=False,
                use_safetensors=True,
                attn_implementation="eager",
            ).to(self._device).eval()
            labels = {name.lower(): index for name, index in self._model.config.label2id.items()}
            self._nli_labels = [labels["contradiction"], labels["entailment"]]
        except (OSError, ValueError, RuntimeError, KeyError) as exc:
            if isinstance(exc, ModelSetupError):
                raise
            raise ModelSetupError(f"Cannot load the local NLI model at {model_dir}: {exc}") from exc
        self._max_length = self._tokenizer.model_max_length
        self._flag_keys = {
            code: tuple(f"{code}:{number}" for number in range(len(phrases)))
            for code, phrases in hypotheses.items()
        }
        self._flag_hypotheses = {
            key: phrase
            for code, phrases in hypotheses.items()
            for key, phrase in zip(self._flag_keys[code], phrases, strict=True)
        }
        self._check_hypothesis_lengths()

    def classify(self, text: str) -> dict[str, float]:
        return self.classify_many([text])[0]

    def classify_many(self, texts: Sequence[str]) -> list[dict[str, float]]:
        return [
            {code: max(scores) for code, scores in row.items()}
            for row in self.score_flag_hypotheses(texts)
        ]

    def score_flag_hypotheses(self, texts: Sequence[str]) -> list[dict[str, list[float]]]:
        """Return each phrase's score in profile order for each input message."""
        return [
            {code: [row[key] for key in keys] for code, keys in self._flag_keys.items()}
            for row in self.score_hypotheses(texts, self._flag_hypotheses)
        ]

    def _check_hypothesis_lengths(self) -> None:
        # Reserve at least one premise token and the tokenizer's pair separators.
        budget = self._max_length - self._tokenizer.num_special_tokens_to_add(pair=True) - 1
        sentences = list(self._flag_hypotheses.values())
        token_ids = self._tokenizer(sentences, add_special_tokens=False, verbose=False).input_ids
        for key, tokens in zip(self._flag_hypotheses, token_ids, strict=True):
            if len(tokens) > budget:
                code, index = key.split(":")
                raise ValueError(f"Hypothesis {int(index) + 1} for {code} exceeds {budget} tokens.")

    def score_hypotheses(
        self, texts: Sequence[str], hypotheses: Mapping[str, str]
    ) -> list[dict[str, float]]:
        """Score complete-sentence hypotheses independently (template `{}`)."""
        results: list[dict[str, float]] = [{} for _ in texts]
        pairs = [
            (index, code, hypothesis)
            for index in range(len(texts))
            for code, hypothesis in hypotheses.items()
        ]
        with self._inference_lock, self._torch.inference_mode():
            for start in range(0, len(pairs), self._batch_size):
                batch = pairs[start : start + self._batch_size]
                inputs = self._tokenizer(
                    [texts[index] for index, _, _ in batch],
                    [hypothesis for _, _, hypothesis in batch],
                    padding=True,
                    truncation="only_first",
                    max_length=self._max_length,
                    return_tensors="pt",
                ).to(self._device)
                logits = self._model(**inputs).logits
                scores = logits[:, self._nli_labels].softmax(dim=-1)[:, 1].tolist()
                for (index, code, _), score in zip(batch, scores, strict=True):
                    results[index][code] = score
        return results
