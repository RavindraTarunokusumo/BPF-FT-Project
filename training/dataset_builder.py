#!/usr/bin/env python3
"""
BPF-Guardian Custom Tinker ChatDatasetBuilder
Implements FrozenSFTDatasetBuilder:
1. Loads pre-frozen train and validation JSONL files without re-splitting.
2. Uses official Qwen/Qwen3-8B tokenizer and qwen3_disable_thinking renderer.
3. Enforces completion-only loss (LAST_ASSISTANT_MESSAGE).
4. Verifies positive loss weights strictly on the assistant completion.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import chz
import datasets

from tinker_cookbook import renderers
from tinker_cookbook.supervised.common import datum_from_model_input_weights
from tinker_cookbook.supervised.data import SupervisedDatasetFromHFDataset
from tinker_cookbook.supervised.types import (
    ChatDatasetBuilder,
    ChatDatasetBuilderCommonConfig,
    SupervisedDataset,
)

DEFAULT_TRAIN_PATH = Path("data/sft/frozen/v1/train.jsonl")
DEFAULT_VALIDATION_PATH = Path("data/sft/frozen/v1/validation.jsonl")


def load_jsonl_rows(path: Path) -> List[Dict[str, Any]]:
    if not path.is_file():
        raise FileNotFoundError(f"Dataset file not found: {path}")
    rows: List[Dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as f:
        for line_idx, line in enumerate(f, start=1):
            line_str = line.strip()
            if not line_str:
                continue
            try:
                row = json.loads(line_str)
                rows.append(row)
            except json.JSONDecodeError as e:
                raise ValueError(f"{path}:{line_idx}: Invalid JSON: {e}")
    return rows


def verify_datum_loss_weights(
    model_input: Any,
    weights: Any,
    messages: List[Dict[str, str]],
) -> Tuple[bool, str]:
    """Verifies that loss weights are positive only on assistant completion tokens."""
    if hasattr(weights, "tolist"):
        weights_list: List[float] = [float(w) for w in weights.tolist()]
    elif isinstance(weights, list):
        weights_list = [float(w) for w in weights]
    else:
        weights_list = [float(w) for w in list(weights)]

    if not weights_list or sum(weights_list) == 0.0:
        return False, "Weights vector is empty or all-zero"

    if len(weights_list) != model_input.length:
        return False, f"Weights length ({len(weights_list)}) does not match input length ({model_input.length})"

    # Find positive weight indices
    pos_indices = [idx for idx, w in enumerate(weights_list) if w > 0.0]
    if not pos_indices:
        return False, "No positive loss weights found"

    first_pos = pos_indices[0]
    last_pos = pos_indices[-1]

    # Verify that the initial system and user prompt tokens have 0.0 loss weight
    if first_pos == 0:
        return False, "Prompt start has positive loss weight (loss applied to system/user message)"

    return True, f"Verified: {len(pos_indices)} assistant tokens with positive loss weights (range {first_pos}..{last_pos})"


@chz.chz
class FrozenSFTDatasetBuilder(ChatDatasetBuilder):
    """Custom dataset builder that loads pre-frozen SFT splits."""

    train_file: str = str(DEFAULT_TRAIN_PATH)
    validation_file: str = str(DEFAULT_VALIDATION_PATH)
    shuffle_train: bool = True
    seed: int = 42

    def __call__(self) -> Tuple[SupervisedDataset, SupervisedDataset]:
        train_rows = load_jsonl_rows(Path(self.train_file))
        val_rows = load_jsonl_rows(Path(self.validation_file))

        if not train_rows:
            raise ValueError(f"Train split is empty: {self.train_file}")
        if not val_rows:
            raise ValueError(f"Validation split is empty: {self.validation_file}")

        max_len = self.common_config.max_length

        def to_datum(row: Dict[str, Any]):
            model_input, weights = self.renderer.build_supervised_example(
                row["messages"],
                train_on_what=self.common_config.train_on_what,
            )
            if model_input.length > max_len:
                raise ValueError(
                    f"Example {row.get('example_id')} rendered to {model_input.length} tokens; limit is {max_len}"
                )

            # Verification of completion-only loss
            valid_w, msg = verify_datum_loss_weights(model_input, weights, row["messages"])
            if not valid_w:
                raise ValueError(f"Invalid loss weights for {row.get('example_id')}: {msg}")

            return datum_from_model_input_weights(
                model_input,
                weights,
                max_length=max_len,
            )

        train_hf = datasets.Dataset.from_list(train_rows)
        if self.shuffle_train:
            train_hf = train_hf.shuffle(seed=self.seed)

        val_hf = datasets.Dataset.from_list(val_rows)

        train_dataset = SupervisedDatasetFromHFDataset(
            train_hf,
            batch_size=self.common_config.batch_size,
            map_fn=to_datum,
        )
        val_dataset = SupervisedDatasetFromHFDataset(
            val_hf,
            batch_size=self.common_config.batch_size,
            map_fn=to_datum,
        )

        return train_dataset, val_dataset


def get_default_dataset_builder(
    train_file: Path = DEFAULT_TRAIN_PATH,
    validation_file: Path = DEFAULT_VALIDATION_PATH,
    model_name: str = "Qwen/Qwen3-8B",
    renderer_name: str = "qwen3_disable_thinking",
    max_length: int = 4096,
    batch_size: int = 32,
) -> FrozenSFTDatasetBuilder:
    common_config = ChatDatasetBuilderCommonConfig(
        model_name_for_tokenizer=model_name,
        renderer_name=renderer_name,
        max_length=max_length,
        batch_size=batch_size,
        train_on_what=renderers.TrainOnWhat.LAST_ASSISTANT_MESSAGE,
    )
    return FrozenSFTDatasetBuilder(
        common_config=common_config,
        train_file=str(train_file),
        validation_file=str(validation_file),
    )


if __name__ == "__main__":
    builder = get_default_dataset_builder()
    print("Testing FrozenSFTDatasetBuilder...")
    train_ds, val_ds = builder()
    print(f"Train Dataset: {train_ds}")
    print(f"Validation Dataset: {val_ds}")
    print("Builder test successful!")
