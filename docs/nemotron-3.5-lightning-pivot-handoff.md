# Handoff: Pivot BPF-Guardian to Nemotron-3.5-Lightning-30B-A3B

**Date:** 2026-09-05  
**Repository:** `RavindraTarunokusumo/BPF-FT-Project`  
**Starting repository state:** commit `187e01e951b404c7b280e5c4b30238162196863b`  
**New model:** `nvidia/NVIDIA-Nemotron-3.5-Lightning-30B-A3B-BF16`  
**Training platform:** Tinker  
**Empirical verification environment:** Hostinger Linux VPS only

## Decision

Pivot the next BPF-Guardian model-development cycle from Qwen3-8B to **Nemotron-3.5-Lightning-30B-A3B**.

Do **not** continue single-turn synthesis RL on Qwen3-8B. Phase 2 demonstrated that the Qwen pipeline is operationally sound but that further synthesis-only RL has little measurable headroom: the selected checkpoint improved the 276-task protected benchmark by only one task, missed both preregistered Dev and Confirmation promotion gates, and was correctly archived.

Qwen3-8B SFT v2 remains the frozen production control until a Nemotron candidate passes the promotion gates below. This is a controlled model replacement, not an immediate production switch.

## Why Lightning

Nemotron 3.5 Lightning is a 30B-total, 3B-active hybrid Mamba-2/attention MoE model released specifically as a starting point for customization through SFT, RL, distillation, and domain adaptation. NVIDIA reports substantial gains over Nemotron 3 Nano on coding-agent evaluations, including SWE-bench Verified (51.56 versus 34.08) and Terminal-Bench 2.1 (24.58 versus 8.29). These generic benchmarks do not prove eBPF competence, but they provide enough prior evidence to justify a controlled BPF evaluation.

Tinker currently supports the BF16 checkpoint directly. At the current limited-time rate, it has the same listed prefill and training prices as Qwen3-8B and a slightly lower sampling price. Recheck pricing immediately before paid runs because the discount is temporary.

Primary references:

- [NVIDIA Nemotron-3.5-Lightning-30B-A3B-BF16 model card](https://huggingface.co/nvidia/NVIDIA-Nemotron-3.5-Lightning-30B-A3B-BF16)
- [Tinker models and pricing](https://tinker-docs.thinkingmachines.ai/tinker/models/)
- [Tinker renderer reference](https://tinker-docs.thinkingmachines.ai/cookbook/api-reference/renderers/get_renderer/)
- [Qwen RLVR Phase 2 findings](https://github.com/RavindraTarunokusumo/BPF-FT-Project/blob/187e01e951b404c7b280e5c4b30238162196863b/docs/rl-phase2-findings-and-decision.md)

## Non-negotiable controls

1. Preserve Qwen3-8B SFT v2 as the production default and comparison anchor.
2. Never train on Calibration, Private Synthesis, Standalone Repair, RL v2 Dev, or RL v2 Confirmation tasks.
3. Compile, load, verify, and behaviorally execute all evaluated BPF programs on the Hostinger Linux VPS. Tinker performs model computation only; Windows may orchestrate but must not verify BPF outputs.
4. Keep the verifier fail-closed. Infrastructure failures must raise an error and must never become numeric model rewards.
5. Maintain paired per-task results so all gains and regressions can be audited.
6. Do not proceed directly to RL. Establish the untuned baseline and complete SFT first.

## Phase N0 — Make the pipeline model-configurable

Create a dedicated experiment branch, for example:

```text
experiment/nemotron-3.5-lightning
```

Remove Qwen-specific defaults from the reusable training and evaluation paths. The repository currently hard-codes `Qwen/Qwen3-8B`, `qwen3_disable_thinking`, Qwen tokenization, and Qwen-specific run paths in multiple files.

Use this primary Nemotron configuration:

```text
model_name: nvidia/NVIDIA-Nemotron-3.5-Lightning-30B-A3B-BF16
renderer_name: nemotron3_ultra_disable_thinking
max_sequence_length: 4096
max_new_tokens: 2048
```

The disabled-thinking renderer is the primary path because the SFT targets contain only final C source, without reasoning traces. Do not train a thinking-enabled renderer against code-only targets.

Required work:

- Centralize model name, renderer, tokenizer, run directory, and checkpoint identifiers in configuration.
- Retain Qwen defaults as a selectable legacy profile.
- Add a Nemotron Lightning profile rather than globally renaming Qwen constants.
- Retokenize every SFT v2 record with the Nemotron tokenizer and renderer.
- Re-run all dataset integrity and maximum-length checks.
- Confirm that completion-only loss still applies exclusively to the final assistant message.
- Add tests proving that both Qwen and Nemotron profiles render, tokenize, sample, and resume correctly.
- Record the OpenMDW 1.1 license and exact model revision in the experiment metadata.

N0 exit gate: the complete test suite passes, every SFT record fits the configured token limit, and a Tinker sampling smoke test produces extractable C source.

## Phase N1 — Untuned empirical baseline

Evaluate the unmodified Nemotron checkpoint before training. Use the same prompts, C-source extraction rules, VPS verifier, fixtures, and per-task reporting used for Qwen.

Primary deterministic evaluation:

```text
renderer: nemotron3_ultra_disable_thinking
temperature: 0.0
seed: 42
num_samples: 1
max_new_tokens: 2048
```

Run:

- 36-task Calibration benchmark
- 120-task Private Synthesis benchmark
- 120-task Standalone Repair benchmark
- 48-task RL v2 Dev set
- 60-task RL v2 Confirmation set

The Dev and Confirmation sets are no longer sealed for the project as a whole, but they remain strictly evaluation-only and provide direct comparison with Phase 2. Label them accordingly; do not describe Confirmation as newly blinded.

Also run a small sampling-sensitivity check on a fixed, stratified subset using NVIDIA's recommended `temperature=1.0`, `top_p=0.95`. Keep it separate from deterministic Pass@1 and do not choose the model based on whichever decoding configuration happens to score better after repeated probing.

Report compilation rate, kernel-verifier rate, behavioral Pass@1, structural compliance, mean reward, and task-level failure stage. Compare against both the original untuned Qwen3-8B baseline and Qwen SFT v2.

N1 decision gate:

- Proceed if untuned Lightning materially exceeds untuned Qwen3-8B and shows no systemic output-format or verifier-safety failure.
- Stop and investigate rendering or extraction if structural compliance is below 99%.
- Do not reject Lightning merely because the untuned model does not yet beat Qwen SFT v2; that is the purpose of N2.

## Phase N2 — Nemotron SFT v1

Train on the frozen, verified SFT v2 dataset. Do not generate a new dataset for the first comparison: holding the data constant isolates the effect of changing the foundation model.

Run a bounded hyperparameter sweep rather than copying Qwen's settings. Start with:

| Run | LoRA rank | Peak learning rate | Schedule |
|---|---:|---:|---|
| A | 32 | `2e-4` | cosine |
| B | 32 | `4e-4` | cosine |
| C | 64 | `2e-4` | cosine |
| D | 64 | `4e-4` | cosine |

Use the frozen validation split and completion-only validation NLL for checkpoint selection. First execute short budget-limited canaries. Expand only configurations that are stable and competitive. Preserve optimizer state, renderer metadata, tokenizer revision, dataset hashes, seed, token counts, and exact Tinker cost for every run.

After selecting the best SFT checkpoint, perform the full empirical evaluation once using the deterministic N1 protocol.

### SFT promotion gates

The Nemotron SFT candidate must satisfy all of the following before replacing Qwen SFT v2:

| Suite | Qwen SFT v2 | Required Nemotron result |
|---|---:|---:|
| RL v2 Dev | 22/48 | at least 25/48 |
| RL v2 Confirmation | 33/60 | at least 36/60 |
| Protected Calibration | 21/36 | at least 20/36 |
| Protected Synthesis | 31/120 | at least 35/120 |
| Protected Repair | 85/120 | at least 85/120 |
| Protected Combined | 137/276 | at least 143/276 |

Additional gates:

- Structural compliance at least 99%.
- Fail-to-pass transitions exceed pass-to-fail transitions.
- No category or difficulty stratum loses more than two tasks.
- All candidate records have empirical VPS evidence and zero mock verification.
- No statistically or operationally suspicious concentration of gains on near-duplicate task families.

If the candidate misses the combined gate narrowly but shows a large, clean synthesis improvement with preserved repair performance, archive it as experimental and conduct one preregistered confirmation run on a newly generated, disjoint 60-task set. Do not weaken the existing gates after seeing results.

## Phase N3 — Diagnostic-guided repair RL

Only begin this phase if Nemotron SFT v1 passes promotion or clearly becomes the strongest experimental checkpoint.

Implement the two-turn environment recommended by the Phase 2 report:

1. The model generates an initial XDP program.
2. The VPS compiles, loads, verifies, and behaviorally tests it.
3. On failure, the environment returns a standardized compiler, verifier, or fixture diagnostic.
4. The model produces one repaired program.
5. The VPS evaluates the repair independently.

Track both initial Pass@1 and final Solve@2. The primary research target is recovery from behavioral failures, especially the previous `0/15` behavioral-repair barrier—not another marginal improvement on already-solved synthesis tasks.

Build a new repair-training pool that is semantically disjoint from every protected suite. Re-run the contamination audit before training. Preserve the Qwen Phase 2 sampler, reward, state-resume, and fail-closed infrastructure improvements where they remain model-agnostic.

## Required deliverables

The implementing agent should commit:

- Model-configurable dataset, SFT, evaluation, and RL paths
- Nemotron tokenizer/render validation report
- Untuned Lightning baseline configuration and complete VPS results
- SFT sweep configurations, logs, costs, and checkpoint manifest
- Paired Qwen-versus-Nemotron transition reports
- Promotion-gate audit and explicit production decision
- If authorized by the N2 outcome, a separate Phase N3 implementation handoff

## Final success condition

The pivot succeeds only if Nemotron produces a reproducible, empirically verified improvement over Qwen3-8B SFT v2—not merely lower validation loss or better generic coding benchmarks. Until those gates are met, Qwen SFT v2 remains the production checkpoint and Nemotron remains an experimental candidate.
