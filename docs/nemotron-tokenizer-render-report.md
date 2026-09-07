# Nemotron-3.5-Lightning Tokenizer & Renderer Validation Report

**Date:** 2026-09-05  
**Model Identifier:** `nvidia/NVIDIA-Nemotron-3.5-Lightning-30B-A3B-BF16`  
**Model Revision (Git SHA):** `a9904d24bcc1d289a1950fa9d2b978c47cf903b9`  
**License:** OpenMDW 1.1 (Open Model Derived Work 1.1)  
**Tokenizer:** Official Nemotron AutoTokenizer (`vocab_size=131072`)  
**Renderer:** `nemotron3_ultra_disable_thinking`  
**Status:** **PHASE N0 EXIT GATE VERIFIED & PASSED**

---

## 1. Executive Summary

As part of Phase N0 of the BPF-Guardian foundation model pivot, the repository pipeline has been transitioned from hard-coded Qwen3-8B assumptions to a modular model-configurable architecture (`training/model_profiles.py`).

Every single record of the verified, frozen SFT v2 dataset (1,600 total records: 1,297 train, 159 in-domain validation, 144 held-out family validation) was retokenized with the official `nvidia/NVIDIA-Nemotron-3.5-Lightning-30B-A3B-BF16` tokenizer and rendered via `nemotron3_ultra_disable_thinking`.

**Zero records exceed the 4,096 token limit** (maximum observed sequence length across all 1,600 examples is 3,797 tokens). Furthermore, completion-only loss masking was empirically proven to apply strictly and exclusively to the assistant completion tokens, with 0.0 weight on system prompt, user prompt, and thinking header tags (`<think></think>`). Live Tinker sampling verified that the model responds with valid, extractable C code.

---

## 2. Model Profile & Architectural Configuration

Centralized in [`training/model_profiles.py`](file:///c:/Users/rvind/OneDrive/Desktop/Projects/BPF-FT-Project/training/model_profiles.py):

| Attribute | Nemotron Profile (Primary) | Qwen Profile (Legacy Control) |
|---|---|---|
| **Profile Key** | `nemotron-3.5-lightning` | `qwen3-8b` |
| **Model Name** | `nvidia/NVIDIA-Nemotron-3.5-Lightning-30B-A3B-BF16` | `Qwen/Qwen3-8B` |
| **Renderer Name** | `nemotron3_ultra_disable_thinking` | `qwen3_disable_thinking` |
| **Max Sequence Length** | 4,096 | 4,096 |
| **Max New Tokens** | 2,048 | 2,048 |
| **Vocab Size** | 131,072 | 151,643 |
| **Stop Sequences** | `[11]` (`<|im_end|>`) | `[151645]` (`<|im_end|>`) |
| **Model Revision** | `a9904d24bcc1d289a1950fa9d2b978c47cf903b9` | `89154f923b09fa5d6aa57c8ec1ae0cfd39c0fa1e` |
| **License** | OpenMDW 1.1 | Apache-2.0 |
| **Tinker Training Price** | $0.44 / M tokens | $0.44 / M tokens |
| **Tinker Prefill Price** | $0.195 / M tokens | $0.195 / M tokens |
| **Tinker Sampling Price** | $0.24 / M tokens | $0.25 / M tokens |

---

## 3. Dataset Token Length Audit (SFT v2 Frozen Splits)

All sequences were rendered using `nemotron3_ultra_disable_thinking` and measured against the 4,096 token limit:

| Dataset Split | Records | Min Length | Max Length | Mean Length | P95 Length | Violations (>4096) | Pass Rate |
|---|---:|---:|---:|---:|---:|---:|---:|
| **`train.jsonl`** | 1,297 | 401 | **3,797** | 1,086.6 | 2,192 | **0** | **100.0%** |
| **`validation_in_domain.jsonl`** | 159 | 401 | **3,787** | 1,051.4 | 2,168 | **0** | **100.0%** |
| **`validation_family_heldout.jsonl`** | 144 | 644 | **1,598** | 979.9 | 1,577 | **0** | **100.0%** |
| **Total / Cumulative** | **1,600** | **401** | **3,797** | **1,073.5** | **2,185** | **0** | **100.0%** |

### Findings
1. **100% Sequence Feasibility**: Every record fits within the 4,096 token limit with comfortable margin (maximum sequence length 3,797 leaves at least 299 tokens of headroom).
2. **Distribution Shift vs Qwen**: The Nemotron Byte-Pair Encoding tokenizer produces sequence lengths closely comparable to Qwen, with slight compression on eBPF helper declarations and struct definitions.

---

## 4. Completion-Only Loss Masking Verification

To guarantee that supervised fine-tuning does not penalize or train on prompt instructions or system guidelines, loss weights were verified on supervised examples:

```python
model_input, weights = renderer.build_supervised_example(messages)
```

Empirical token-by-token weight analysis:
- `<|im_start|>system\n...<|im_end|>`: Loss weight = `0.0` (Masked)
- `<|im_start|>user\n...<|im_end|>`: Loss weight = `0.0` (Masked)
- `<|im_start|>assistant\n<think></think>`: Loss weight = `0.0` (Masked)
- Assistant C code tokens: Loss weight = `1.0` (Trained)
- `<|im_end|>`: Loss weight = `1.0` (Trained)

**Conclusion**: Loss applies exclusively to the assistant completion and termination token. System prompts, task instructions, and thinking markers are 100% masked.

---

## 5. Live Tinker Sampling Smoke Test

A live sampling test was executed against `nvidia/NVIDIA-Nemotron-3.5-Lightning-30B-A3B-BF16` on Tinker:

```text
Prompt:
<|im_start|>system
You are a helpful assistant.<|im_end|>
<|im_start|>user
Say hello in C: write just one comment /* hello */<|im_end|>
<|im_start|>assistant
<think></think>

Generated Output:
```c
/* hello */
```<|im_end|>
```

- **Stop token emitted**: Token `11` (`<|im_end|>`).
- **Generation status**: Complete and structurally compliant.
- **C Source Extracted**: `/* hello */\n` (clean, uncorrupted).

---

## 6. Pipeline Test Suite Certification

The full automated test suite was executed:

```bash
pytest tests/
```

**Result:**
- 94 passed
- 4 skipped (live VPS kernel verification integration tests, which run on the VPS)
- 0 failures, 0 errors

**Exit Gate Signoff**: Phase N0 is complete. Proceed to Phase N1 (Untuned empirical baseline evaluation on the Hostinger Linux VPS).
