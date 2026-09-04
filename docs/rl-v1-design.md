# BPF-Guardian RLVR Phase 1: Technical Design Specification

## 1. Executive Summary & Mission

The objective of **BPF-Guardian RLVR Phase 1** is to reinforce the `Qwen/Qwen3-8B` language model (starting from supervised fine-tuning checkpoint `SFT v2`) using verifiable rewards derived from actual Linux kernel eBPF compilation, verification, and packet execution on a dedicated Hostinger Linux VPS (`srv1534562`).

The model is optimized specifically for one-shot eBPF/XDP synthesis correctness, with behavioral execution pass rate as the dominant reward signal.

---

## 2. Strict Architectural Boundary

Execution boundaries are enforced at both network and operating system layers:

```text
┌─────────────────────────────────────────────────────────────┐
│                       TINKER CLUSTER                        │
│ - Qwen3-8B model sampling (T=0.8 for RL, T=0.0 for eval)   │
│ - Forward / backward gradient passes (LoRA rank 32)        │
│ - Importance sampling loss & group-relative advantages     │
│ - KL penalty regularization vs frozen SFT v2 checkpoint     │
│ - Optimizer weight updates & checkpoint storage            │
└──────────────────────────────┬──────────────────────────────┘
                               │ Sampling & Gradients
                               ▼
┌─────────────────────────────────────────────────────────────┐
│                    HOSTINGER LINUX VPS                      │
│ - Master RL controller (train_rl.py, evaluate_rl.py)        │
│ - Prompt & rollout orchestration (BPFEnv, BPFEnvGroupBuilder)│
│ - Isolated per-rollout candidate persistence                │
│ - Clang BPF compilation (-target bpf -O2 -g)                │
│ - Linux kernel verifier loading (bpftool -d prog load)      │
│ - Behavioral packet test execution (bpftool prog run)       │
│ - Guaranteed fail-closed cleanup (unpin / unlink)           │
│ - Multi-stage bounded reward calculation (0.00 to 1.00)     │
│ - Full audit trail (SHA-256 hashes & raw verification logs) │
└─────────────────────────────────────────────────────────────┘
```

### Prohibitions
1. Generated C code **never** executes on Tinker servers.
2. Generated C code **never** executes on the user's local Windows machine.
3. No production reward may ever be computed via mock or simulated verifiers.

---

## 3. RL Runtime & Abstractions

Using Tinker's official RL abstractions:
- **`RLDataset` / `RLDatasetBuilder`**: `BPFRLDatasetBuilder` loads task instances from `data/rl/v1/train` and `data/rl/v1/dev` with strict fail-closed benchmark isolation.
- **`EnvGroupBuilder`**: `BPFEnvGroupBuilder` constructs groups of 4 parallel environments per problem instance to provide group-relative advantage baselines (e.g. GRPO / importance sampling).
- **`Env`**: `BPFEnv` is a single-turn asynchronous environment that provides the synthesis prompt, captures generated C source, dispatches kernel verification, computes shaped reward, and terminates the episode.
- **Constant Reward Filtering**: Groups where all completions receive identical rewards provide zero gradient advantage and are filtered out via `remove_constant_reward_groups=True`.

---

## 4. VPS Kernel Reward Executor & Isolation

### Isolation & Execution Contract
Untrusted candidate C code is evaluated strictly under isolation:
- `shell=False` with argument arrays.
- Per-rollout isolated directories under `runs/tinker/qwen3-8b-bpf-rl-v1/verifier_records/<rollout_id>/`.
- Explicit subprocess timeouts:
  - Compilation: 30 seconds.
  - Verifier loading: 30 seconds.
  - Packet test run: 10 seconds per fixture.
- Dedicated BPF pin names: `/sys/fs/bpf/bpf_rlvr_<rollout_id>_<pid>`.
- Guaranteed `finally` cleanup unpinning and deleting temporary files.
- Concurrency bounded by `asyncio.Semaphore(2)`.

### Fail-Closed Infrastructure Error Policy
Failures resulting from toolchain unavailability, corrupted records, timeout anomalies, or cleanup errors are classified as **infrastructure errors**. They **never** become model failure rewards ($0.0$). Rollouts encountering infrastructure failures are excluded from training updates.

---

## 5. Multi-Stage Bounded Reward Function

$$\text{Reward} = 0.02 \cdot C_{\text{compliance}} + 0.08 \cdot C_{\text{compile}} + 0.15 \cdot C_{\text{verifier}} + 0.70 \cdot F_{\text{weighted\_pass}} + 0.05 \cdot B_{\text{complete}}$$

| Component | Weight | Condition |
| :--- | :---: | :--- |
| **Compliance** | 0.02 | Valid C source only (starts with code, includes, SEC("xdp"), GPL license, no fences, no FAULT/TODO markers). |
| **Compilation** | 0.08 | Clang BPF target succeeds and produces valid ELF object. |
| **Verifier** | 0.15 | Passed compilation AND Linux kernel verifier accepts program without rejection. |
| **Behavioral** | 0.70 | Passed verifier AND executes packet fixtures with `BPF_PROG_TEST_RUN`, weighted by test complexity. |
| **Full Suite** | 0.05 | 100% of declared fixtures pass expected action. |
| **Total** | **1.00** | Bounded maximum achievable reward. |

---

## 6. Task Pool Architecture & Benchmark Isolation

The task pool is structured into 132 tasks across 4 categories and 3 difficulty levels:
- **Canary Pool**: 12 tasks (1 per cell)
- **Training Pool**: 96 tasks (8 per cell)
- **Development Pool**: 24 tasks (2 per cell)

### Strict Benchmark Isolation
All 132 tasks are cryptographically verified to have **zero overlap** with the 276 protected benchmark tasks:
- `data/calibration/index.jsonl` (36 tasks)
- `data/benchmark/synthesis/index.jsonl` (120 tasks)
- `data/benchmark/repair/index.jsonl` (120 tasks)

Every task includes a verified reference C solution (`solution.c`) pre-validated on the Hostinger Linux VPS with 100% compilation, verifier acceptance, and packet test pass rate.
Aggregate Task Pool Hash: `bd62dc1dea4d48ef9fe04017e9c6de2f355664184221a2351c23bdc3eac48fcd`.

---

## 7. Advancement Gates & Selection Criteria

Checkpoint selection is driven solely by the RL development set at $T=0.0$.
A trained checkpoint is promoted if and only if:
1. All production rewards were computed empirically on the VPS kernel harness.
2. Zero protected evaluation tasks entered training or development sets.
3. Development functional Pass@1 improves by $\ge 5.0$ percentage points over baseline.
4. Development compliance remains $\ge 99.0\%$.
5. Protected synthesis does not regress by $>3$ tasks from $31/120$.
6. Protected repair does not regress by $>5$ tasks from $85/120$.
7. Checkpoints and sampler weights restore cleanly.
