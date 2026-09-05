"""
BPF-Guardian Model Profile Configuration & Abstraction Layer
============================================================
Centralizes foundation model identifiers, renderers, tokenizers, stop sequences,
extraction rules, and operational constraints for BPF-Guardian:
- Nemotron-3.5-Lightning-30B-A3B (primary)
- Qwen3-8B (legacy comparison control)
"""

from __future__ import annotations

import dataclasses
import os
import re
from typing import Any, Dict, List, Optional, Union


@dataclasses.dataclass(frozen=True)
class ModelProfile:
    """Configuration profile for a foundation model family."""

    name: str
    model_name: str
    renderer_name: str
    max_sequence_length: int = 4096
    max_new_tokens: int = 2048
    family: str = "nemotron"
    license: str = "OpenMDW-1.1"
    revision: str = "a9904d24bcc1d289a1950fa9d2b978c47cf903b9"
    default_temperature: float = 0.0
    train_price_per_m_tokens: float = 0.44
    prefill_price_per_m_tokens: float = 0.195
    sampling_price_per_m_tokens: float = 0.24

    def get_tokenizer(self) -> Any:
        """Loads and returns the official AutoTokenizer for this profile."""
        from transformers import AutoTokenizer

        return AutoTokenizer.from_pretrained(self.model_name)

    def get_renderer(self, tokenizer: Optional[Any] = None) -> Any:
        """Loads and returns the Tinker renderer for this profile."""
        from tinker_cookbook.renderers import get_renderer

        if tokenizer is None:
            tokenizer = self.get_tokenizer()
        return get_renderer(self.renderer_name, tokenizer=tokenizer)

    def get_stop_sequences(self, tokenizer: Optional[Any] = None) -> List[int]:
        """Returns integer token IDs used as sampling stop sequences."""
        renderer = self.get_renderer(tokenizer=tokenizer)
        return list(renderer.get_stop_sequences())

    def clean_raw_text(self, raw_text: str) -> str:
        """Strips thinking blocks, chat markers, and special tokens from raw response."""
        text = re.sub(r"<think>.*?</think>", "", raw_text, flags=re.DOTALL).strip()
        text = re.sub(r"<\|im_end\|>.*$", "", text, flags=re.DOTALL).strip()
        text = re.sub(r"<\|.*?\|>", "", text).strip()
        return text

    def extract_c_source(self, raw_text: str) -> str:
        """Extracts C code from model response, stripping fences, thinking preambles, and tokens."""
        text = self.clean_raw_text(raw_text)

        # 1. Markdown code block
        match = re.search(r"```(?:c|C|cpp)?\s*(.*?)\s*```", text, re.DOTALL)
        if match:
            code = match.group(1).strip()
            code = re.sub(r"<\|.*?\|>", "", code).strip()
            return code + "\n"

        # 2. Starts from first include or comment header
        include_match = re.search(r"((?:/\*.*?\*/\s*|//.*?\n\s*)*#include\s+<.*)", text, re.DOTALL)
        if include_match:
            code = include_match.group(1).strip()
            code = re.sub(r"<\|.*?\|>", "", code).strip()
            return code + "\n"

        # 3. Starts from SEC("xdp")
        sec_match = re.search(r"(SEC\s*\(\s*\"xdp\"\s*\).*)", text, re.DOTALL)
        if sec_match:
            code = sec_match.group(1).strip()
            code = re.sub(r"<\|.*?\|>", "", code).strip()
            return code + "\n"

        return text + "\n"

    def check_output_compliance(self, raw_text: str) -> Dict[str, Any]:
        """Checks if the raw output adheres strictly to the C source contract."""
        text = re.sub(r"<think>.*?</think>", "", raw_text, flags=re.DOTALL).strip()
        text = re.sub(r"<\|.*?\|>", "", text).strip()

        has_fences = "```" in text
        has_include = "#include" in text
        has_sec = "SEC(" in text
        has_license = "char _license[]" in text or "char LICENSE[]" in text or "LICENSE" in text
        has_xdp = "xdp" in text.lower() or "XDP_" in text

        fault_match = bool(
            re.search(
                r"(\bFAULT:\b|\/\/\s*FAULT:|\/\*\s*FAULT:|\bTODO:\b|\bFIXME:\b)",
                text,
                re.IGNORECASE,
            )
        )

        starts_with_code = (
            text.startswith("#include") or text.startswith("/*") or text.startswith("//")
        )

        compliant = (
            not has_fences
            and starts_with_code
            and has_include
            and has_sec
            and has_license
            and has_xdp
            and not fault_match
        )

        return {
            "compliant": compliant,
            "has_fences": has_fences,
            "starts_with_code": starts_with_code,
            "has_include": has_include,
            "has_sec": has_sec,
            "has_license": has_license,
            "has_xdp": has_xdp,
            "has_fault_markers": fault_match,
        }


# Pre-registered model profiles
NEMOTRON_PROFILE = ModelProfile(
    name="nemotron-3.5-lightning",
    model_name="nvidia/NVIDIA-Nemotron-3.5-Lightning-30B-A3B-BF16",
    renderer_name="nemotron3_ultra_disable_thinking",
    max_sequence_length=4096,
    max_new_tokens=2048,
    family="nemotron",
    license="OpenMDW-1.1",
    revision="a9904d24bcc1d289a1950fa9d2b978c47cf903b9",
    default_temperature=0.0,
    train_price_per_m_tokens=0.44,
    prefill_price_per_m_tokens=0.195,
    sampling_price_per_m_tokens=0.24,
)

QWEN_LEGACY_PROFILE = ModelProfile(
    name="qwen3-8b",
    model_name="Qwen/Qwen3-8B",
    renderer_name="qwen3_disable_thinking",
    max_sequence_length=4096,
    max_new_tokens=2048,
    family="qwen",
    license="Apache-2.0",
    revision="89154f923b09fa5d6aa57c8ec1ae0cfd39c0fa1e",
    default_temperature=0.0,
    train_price_per_m_tokens=0.44,
    prefill_price_per_m_tokens=0.195,
    sampling_price_per_m_tokens=0.25,
)

_REGISTRY: Dict[str, ModelProfile] = {
    "nemotron-3.5-lightning": NEMOTRON_PROFILE,
    "nemotron": NEMOTRON_PROFILE,
    "nemotron-lightning": NEMOTRON_PROFILE,
    "nvidia/NVIDIA-Nemotron-3.5-Lightning-30B-A3B-BF16": NEMOTRON_PROFILE,
    "qwen3-8b": QWEN_LEGACY_PROFILE,
    "qwen": QWEN_LEGACY_PROFILE,
    "Qwen/Qwen3-8B": QWEN_LEGACY_PROFILE,
}


def get_model_profile(name_or_profile: Optional[Union[str, ModelProfile]] = None) -> ModelProfile:
    """Returns the ModelProfile for the requested profile name or default."""
    if isinstance(name_or_profile, ModelProfile):
        return name_or_profile

    if name_or_profile is not None:
        key = str(name_or_profile).strip()
        if key in _REGISTRY:
            return _REGISTRY[key]
        raise KeyError(
            f"Unknown model profile: '{name_or_profile}'. Available profiles: {list(_REGISTRY.keys())}"
        )

    env_profile = os.environ.get("BPF_MODEL_PROFILE", "nemotron-3.5-lightning").strip()
    if env_profile in _REGISTRY:
        return _REGISTRY[env_profile]

    return NEMOTRON_PROFILE


def list_model_profiles() -> List[str]:
    """Returns the list of unique canonical profile names."""
    return ["nemotron-3.5-lightning", "qwen3-8b"]
