"""Shared paths and model revision for setup and offline inference."""

from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent.parent
MODEL_ID = "MoritzLaurer/multilingual-MiniLMv2-L6-mnli-xnli"
MODEL_REVISION = "0a71e92a985b6e1ad1828cf67ce9c459639c1dca"
DEFAULT_MODEL_DIR = PROJECT_ROOT / "models" / MODEL_ID.rsplit("/", 1)[1]
MODEL_FILES = (
    "config.json",
    "model.safetensors",
    "sentencepiece.bpe.model",
    "special_tokens_map.json",
    "tokenizer.json",
    "tokenizer_config.json",
)
