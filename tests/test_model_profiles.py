"""
Tests for BPF-Guardian Model Profile Configuration Layer
========================================================
Validates:
1. Profile registry lookup (Nemotron and Qwen).
2. Tokenizer and renderer loading.
3. Chat template / generation prompt formatting.
4. Completion-only supervised loss weights masking.
5. C source extraction across diverse LLM completion formats.
6. Structural compliance checking.
"""

from __future__ import annotations

import pytest

from training.model_profiles import (
    NEMOTRON_PROFILE,
    QWEN_LEGACY_PROFILE,
    ModelProfile,
    get_model_profile,
    list_model_profiles,
)


def test_profile_registry_lookup():
    p_nemo = get_model_profile("nemotron-3.5-lightning")
    assert p_nemo.name == "nemotron-3.5-lightning"
    assert p_nemo.family == "nemotron"
    assert p_nemo.license == "OpenMDW-1.1"
    assert p_nemo.revision == "a9904d24bcc1d289a1950fa9d2b978c47cf903b9"

    p_qwen = get_model_profile("qwen3-8b")
    assert p_qwen.name == "qwen3-8b"
    assert p_qwen.family == "qwen"
    assert p_qwen.license == "Apache-2.0"

    # Default profile is Nemotron
    p_def = get_model_profile()
    assert p_def.name == "nemotron-3.5-lightning"

    # Profile listing
    profiles = list_model_profiles()
    assert "nemotron-3.5-lightning" in profiles
    assert "qwen3-8b" in profiles

    with pytest.raises(KeyError):
        get_model_profile("non_existent_model_profile")


def test_nemotron_tokenizer_and_renderer():
    profile = get_model_profile("nemotron-3.5-lightning")
    tokenizer = profile.get_tokenizer()
    assert tokenizer is not None
    assert len(tokenizer) == 131072

    renderer = profile.get_renderer(tokenizer=tokenizer)
    assert renderer is not None
    assert renderer.__class__.__name__ == "Nemotron3UltraDisableThinkingRenderer"

    stop_seqs = profile.get_stop_sequences(tokenizer=tokenizer)
    assert stop_seqs == [11]  # <|im_end|>


def test_nemotron_prompt_generation_format():
    profile = get_model_profile("nemotron-3.5-lightning")
    tokenizer = profile.get_tokenizer()
    renderer = profile.get_renderer(tokenizer=tokenizer)

    messages = [
        {"role": "system", "content": "You are an eBPF expert."},
        {"role": "user", "content": "Write an XDP program."},
    ]
    prompt_input = renderer.build_generation_prompt(messages)
    tokens = prompt_input.to_ints()
    decoded = tokenizer.decode(tokens)

    # In disabled-thinking mode, Nemotron begins assistant turn with <think></think>
    assert "<|im_start|>system" in decoded
    assert "<|im_start|>user" in decoded
    assert "<|im_start|>assistant\n<think></think>" in decoded


def test_completion_only_loss_weights():
    profile = get_model_profile("nemotron-3.5-lightning")
    tokenizer = profile.get_tokenizer()
    renderer = profile.get_renderer(tokenizer=tokenizer)

    messages = [
        {"role": "system", "content": "You are an eBPF expert."},
        {"role": "user", "content": "Write an XDP filter."},
        {"role": "assistant", "content": '/* code */\nSEC("xdp") int prog() { return 2; }\nchar _license[] SEC("license") = "GPL";'},
    ]

    res = renderer.build_supervised_example(messages)
    model_input, weights = res[0], res[1]
    tokens = model_input.to_ints()
    weights_list = [float(w) for w in weights.tolist()]

    assert len(tokens) == len(weights_list)

    # First tokens (system and user) must have weight 0.0
    assert weights_list[0] == 0.0

    # Ensure positive weights are present and strictly apply to the assistant completion
    pos_indices = [idx for idx, w in enumerate(weights_list) if w > 0.0]
    assert len(pos_indices) > 0

    first_pos = pos_indices[0]
    # The first token with weight > 0 should correspond to the start of assistant content
    pos_tokens = [tokens[i] for i in pos_indices]
    decoded_pos = tokenizer.decode(pos_tokens)
    assert "/* code */" in decoded_pos
    assert "You are an eBPF expert." not in decoded_pos
    assert "Write an XDP filter." not in decoded_pos


def test_c_source_extraction():
    profile = get_model_profile("nemotron-3.5-lightning")

    # Fenced markdown code
    fenced = """```c
#include <linux/bpf.h>
SEC("xdp")
int xdp_prog(struct xdp_md *ctx) { return 2; }
char _license[] SEC("license") = "GPL";
```"""
    c1 = profile.extract_c_source(fenced)
    assert "#include <linux/bpf.h>" in c1
    assert "```" not in c1

    # Raw C starting with comments and includes
    raw = """/* Header comment */
#include <linux/bpf.h>
SEC("xdp")
int xdp_prog(struct xdp_md *ctx) { return 2; }
char _license[] SEC("license") = "GPL";
<|im_end|>"""
    c2 = profile.extract_c_source(raw)
    assert "#include <linux/bpf.h>" in c2
    assert "<|im_end|>" not in c2

    # Thinking tags stripped
    with_think = """<think>I need to write an XDP program.</think>
```c
#include <linux/bpf.h>
SEC("xdp")
int xdp_prog(struct xdp_md *ctx) { return 2; }
char _license[] SEC("license") = "GPL";
```"""
    c3 = profile.extract_c_source(with_think)
    assert "I need to write" not in c3
    assert "#include <linux/bpf.h>" in c3


def test_check_output_compliance():
    profile = get_model_profile("nemotron-3.5-lightning")

    compliant_code = """#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int xdp_prog(struct xdp_md *ctx) {
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
"""
    comp = profile.check_output_compliance(compliant_code)
    assert comp["compliant"] is True
    assert comp["has_include"] is True
    assert comp["has_sec"] is True
    assert comp["has_license"] is True
    assert comp["has_xdp"] is True
    assert comp["has_fences"] is False

    # Violations: markdown fences
    non_comp_fences = "```c\n" + compliant_code + "```\n"
    assert profile.check_output_compliance(non_comp_fences)["compliant"] is False

    # Violations: FAULT marker
    non_comp_fault = compliant_code + "\n// FAULT: incorrect check\n"
    assert profile.check_output_compliance(non_comp_fault)["compliant"] is False

    # Violations: Missing license
    non_comp_nolic = """#include <linux/bpf.h>
SEC("xdp")
int xdp_prog(struct xdp_md *ctx) { return 2; }
"""
    assert profile.check_output_compliance(non_comp_nolic)["compliant"] is False
