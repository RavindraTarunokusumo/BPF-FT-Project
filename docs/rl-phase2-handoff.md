# Handoff: Qwen3-8B BPF RLVR Phase 2 — Controlled Generalization Experiment

## Decision

Proceed with a second RLVR experiment, but do not implement the recommendations in the Phase 1 findings report unchanged.

Phase 1 established that the empirical Tinker-to-VPS RL pipeline works. It did not establish that the RL policy is better than SFT v2:

- checkpoint `000035` improved the 24-task development set by only one task, from `17/24` to `18/24`;
- the selected checkpoint fell from `31/120` to `29/120` on protected synthesis;
- the combined protected result fell from `137/276` to `134/276`;
- standalone repair remained `85/120`;
- the selected development checkpoint was chosen after repeated evaluation on the same small development set.

SFT v2 must remain the default checkpoint. RL Phase 1 checkpoint `000035` remains an archived experimental artifact.

Phase 2 should test a narrower hypothesis:

> Can difficulty-aware sampling, a larger task-family-disjoint training pool, and a more conservative optimization schedule improve one-shot synthesis without changing the proven empirical reward definition or degrading repair capability?

Do not add map-structure bonuses, length penalties, or repair co-training in this experiment. Those changes would introduce additional reward-hacking risks and make the result difficult to attribute.

## Repository and reviewed evidence

Repository:

```text
RavindraTarunokusumo/BPF-FT-Project
```

Expected starting commit:

```text
50b219c72b4a858b0862ff01620229341a6bc700
```

Pull the latest `main` before making changes and record the actual starting SHA.

Evidence reviewed:

- [RL Phase 1 findings and recommendations](https://github.com/RavindraTarunokusumo/BPF-FT-Project/blob/50b219c72b4a858b0862ff01620229341a6bc700/docs/rl-v1-findings-and-phase2-recommendations.md)
- [RL Phase 1 pilot report](https://github.com/RavindraTarunokusumo/BPF-FT-Project/blob/50b219c72b4a858b0862ff01620229341a6bc700/runs/tinker/qwen3-8b-bpf-rl-v1/pilot_report.md)
- `training/rl/config.py`
- `training/rl/dataset.py`
- `training/rl/reward.py`
- `training/rl/bpf_env.py`
- `training/rl/train_rl.py`
- committed evaluation summaries and transition records
- repository commit [`50b219c`](https://github.com/RavindraTarunokusumo/BPF-FT-Project/commit/50b219c72b4a858b0862ff01620229341a6bc700)

Relevant Tinker references:

- [RL architecture](https://tinker-docs.thinkingmachines.ai/cookbook/rl/)
- [Configuration-based RL](https://tinker-docs.thinkingmachines.ai/tutorials/cookbook-abstractions/rl-with-config/)
- [RL hyperparameters](https://tinker-docs.thinkingmachines.ai/tutorials/advanced/rl-hyperparams/)
- [Tinker loss functions](https://tinker-docs.thinkingmachines.ai/tinker/losses/)

## Checkpoints

### Production default and Phase 2 initialization

Training-state checkpoint:

```text
tinker://9461002d-2321-5858-8184-5604f9304283:train:0/weights/final
```

Sampler checkpoint:

```text
tinker://9461002d-2321-5858-8184-5604f9304283:train:0/sampler_weights/final
```

Use frozen SFT v2 as both:

- the Phase 2 starting policy;
- the KL reference policy.

Start Phase 2 from SFT v2 rather than RL Phase 1 checkpoint `000035`. This makes the effect of the Phase 2 curriculum and optimization changes interpretable and avoids continuing from a checkpoint that failed promotion.

### Archived RL Phase 1 checkpoint

```text
tinker://a5e21df2-a4fe-54ce-9781-800ce6c75689:train:0/sampler_weights/000035
```

Do not assume that a restorable training-state checkpoint exists at `/weights/000035`. Locate and validate it if needed for analysis, but do not use it to initialize Phase 2 without an explicit change to this experiment design.

## Empirical Phase 1 baseline

### RL training

```text
Training steps:                 50
Problem groups per step:        2
Completions per group:          4
Training rollouts:              400
Constant-reward groups:         62.0%
Mixed-reward groups:            38.0%
Average rollout reward:         0.7808
Compilation pass rate:          87.2%
Kernel-verifier pass rate:      85.8%
Functional pass rate:           64.2%
Reported mean KL metric:        0.001675
Reported maximum KL metric:     0.008570
```

### Development trajectory at temperature 0.0

| Checkpoint | Functional Pass@1 | Compile | Verifier | Mean reward |
|---|---:|---:|---:|---:|
| SFT v2 | 17/24 | 22/24 | 22/24 | 0.8431 |
| `000015` | 16/24 | 22/24 | 22/24 | 0.8264 |
| `000025` | 16/24 | 22/24 | 22/24 | 0.8264 |
| `000035` | 18/24 | 24/24 | 24/24 | 0.9097 |
| `000045` | 17/24 | 23/24 | 23/24 | 0.8681 |
| `000050` | 16/24 | 22/24 | 22/24 | 0.8264 |
| final | 16/24 | 22/24 | 22/24 | 0.8264 |

One task represents `4.17` percentage points on this development set. The original “at least +5 percentage points” gate therefore cannot be met by exactly five points: the first attainable passing result is `19/24`, which is two tasks and `+8.33` points above the `17/24` baseline.

### Protected evaluation at temperature 0.0

| Suite | SFT v2 | RL `000035` | Fail→pass | Pass→fail | Net | Exact McNemar p |
|---|---:|---:|---:|---:|---:|---:|
| Calibration synthesis | 21/36 | 20/36 | 2 | 3 | -1 | 1.0000 |
| Private synthesis | 31/120 | 29/120 | 3 | 5 | -2 | 0.7266 |
| Standalone repair | 85/120 | 85/120 | 0 | 0 | 0 | 1.0000 |
| Combined | 137/276 | 134/276 | 5 | 8 | -3 | 0.5811 |

Interpret these results precisely:

- The protected results do not show a statistically significant difference under the exact McNemar tests.
- Failure to reject the null does not prove that there was “zero regression.”
- The observed point estimates contain three net regressions overall and two on the primary synthesis benchmark.
- The `85/85` retained repair passes are encouraging evidence of retention in this evaluation, not proof that repair capability is universally preserved.
- Development improvement is inconclusive because it is `+1` task on a small set used repeatedly for checkpoint selection.

### Empirical execution count

The report accounts for:

```text
Sampling-only canary:      48 rollouts
Five-step canary:          40 rollouts
Pilot training:           400 rollouts
Dev checkpoint evaluation:168 rollouts
Protected evaluation:     276 rollouts
Total:                    932 rollouts
```

Before Phase 2, locate the corresponding VPS raw records and validate the count. The repository ignores large verifier-record directories, so committed summaries alone are not sufficient to reconstruct all empirical claims.

## Assessment of the proposed recommendations

| Proposed recommendation | Decision | Assessment |
|---|---|---|
| Dynamic difficulty curriculum | Accept with changes | The `62%` constant-group rate justifies improving task selection. However, `BPFRLDataset.get_batch()` currently performs deterministic round-robin traversal, not uniform random sampling. First reconstruct train-only results by task and stratum, then implement a seeded, auditable priority sampler. |
| Increase training from 50 to 100 steps | Reject as the default | Phase 1 peaked at step 35 and degraded afterward. The evidence supports stronger early stopping and a lower learning rate, not blindly doubling the budget. |
| Cosine learning-rate decay | Conditionally accept | Use only if supported by the pinned Tinker/cookbook API and recorded in the serialized run configuration. Do not implement an undocumented scheduler or claim decay while using a scalar constant rate. |
| Add `+0.05` map-structure reward | Reject for Phase 2 | Correct map declaration does not solve the observed LPM-key semantic failure. A static or regex-based map grader can be gamed and may reward code that is verifier-valid but behaviorally wrong. |
| Add a code-length penalty | Reject | Shorter BPF code is not inherently safer or more correct. A penalty could suppress required bounds checks and verifier-safe boilerplate. Track tokens and BPF instruction count as diagnostics only. |
| Mix 15–20% repair tasks | Defer | Repair did not regress on the frozen benchmark. Mixing objectives now would obscure whether synthesis curriculum changes work. Implement diagnostic repair RL as a separate Phase 3 experiment. |
| Target the specific failed dev LPM task | Reject | `rl_dev_nrf_l3_01` has already influenced analysis. Do not train on it, clone it, or hand-design prompts around its exact failure. Add independently generated LPM task families to training and keep semantic-family separation. |

## Mission

Implement and run RLVR Phase 2 as a controlled synthesis experiment with:

1. a complete audit of the Phase 1 evidence;
2. new task-family-disjoint RL v2 data;
3. a seeded train-only difficulty-aware sampler;
4. unchanged behavior-dominant empirical rewards;
5. conservative optimization and real checkpoint evaluation;
6. a new locked confirmation set;
7. one frozen protected evaluation after checkpoint selection.

The RL controller and all generated-code execution must run on the Hostinger Linux VPS. Tinker may perform sampling, forward/backward computation, optimization, and checkpoint storage only.

## Scope

### In scope

- Correcting the statistical and KL language in the Phase 1 reports.
- Auditing Phase 1 raw empirical records.
- Hardening infrastructure-error behavior in the reward API.
- Semantic contamination detection beyond task-ID checks.
- A new RL v2 train, selection-dev, and locked-confirmation dataset.
- Difficulty- and category-aware sampling based only on training rollouts.
- Conservative learning-rate scheduling when supported.
- Proper checkpoint evaluation and early stopping.
- VPS empirical evaluation of all generated candidates.
- Paired comparisons with SFT v2.
- Tests, manifests, hashes, and reproduction commands.

### Out of scope

- Promoting RL Phase 1 checkpoint `000035`.
- Training from `000035`.
- Editing protected benchmarks or their fixtures.
- Using protected or development failures as training examples.
- Map-structure or source-pattern rewards.
- Code-length penalties.
- Repair co-training.
- Multi-turn synthesis→repair RL.
- Pass@k evaluation.
- Per-task prompt tuning.
- Generating a publication lockbox in this task.
- Executing generated BPF code on Tinker or Windows.

## Phase 0: Audit and correct Phase 1

Do not begin paid Phase 2 training until this audit is complete.

### Raw-record audit

On the VPS, locate all Phase 1 candidates and raw verifier records for the 932 accounted rollouts.

For each rollout, verify:

- exact task ID and rollout ID;
- candidate source exists;
- source SHA-256 matches;
- task and prompt-template hashes match;
- `verification_mode` is empirical;
- Clang execution was attempted;
- kernel loading was attempted when compilation passed;
- all expected fixtures ran when verifier loading passed;
- fixture counts and weights match the task manifest;
- reward recomputation matches the recorded reward;
- infrastructure failures were excluded from training;
- cleanup succeeded;
- no mock record entered training or evaluation.

Create an aggregate manifest containing:

- record count by run stage;
- candidate-set hash;
- raw-record-set hash;
- reward-record-set hash;
- missing or invalid records;
- VPS kernel and toolchain;
- repository commit;
- Tinker and cookbook versions.

If all 932 raw records cannot be recovered, document exactly which records are missing. Do not repeat unsupported task-level claims such as Level 1 saturation unless the required training records are available.

### Report corrections

Correct the Phase 1 report language:

- Replace “zero statistically significant regression” with “no statistically significant difference was detected.”
- Replace “proving repair capability was preserved” with “all 85 previously passing repair tasks were retained in this deterministic evaluation.”
- Do not compare `max KL = 0.008570` to `beta = 0.05` as though `beta` were a divergence threshold. `0.05` is the KL penalty coefficient.
- Identify which KL metric was recorded, when it was computed, and how it was aggregated.
- Note that the committed Phase 1 configuration has `compute_post_kl: false`.
- State that checkpoint `000035` was selected using repeated measurements on a 24-task development set.
- State that protected synthesis and combined point estimates declined.

Preserve the original numerical results while correcting their interpretation.

## Phase 1: Harden reusable RL infrastructure

### Infrastructure errors must not be numeric rewards

`BPFEnv.step()` currently raises when `verification.infrastructure_error` is true, which is correct. However, `compute_rlvr_reward()` independently returns a numeric `0.0` reward for an infrastructure error.

Change the reusable reward API so an infrastructure failure cannot accidentally be consumed as a valid model failure.

Use one of these fail-closed approaches:

- raise a dedicated `InfrastructureRewardError`; or
- return an explicit invalid result with no scalar reward.

Do not return `0.0` for infrastructure failures.

Add tests proving that:

- the environment excludes infrastructure failures from training;
- direct reward-function callers cannot obtain a numeric reward for them;
- retry does not submit duplicate rewards;
- a fixture-count mismatch is treated as invalid infrastructure, not model failure.

### Semantic contamination checks

The current loader blocks matching protected task IDs but does not prove semantic disjointness.

Add stable fingerprints for:

- normalized task instruction;
- normalized requirements;
- protocol and feature tuple;
- task-family identifier;
- fixture schema;
- public prompt;
- complete task manifest.

Fail closed if RL v2 train, dev, or confirmation tasks duplicate or near-duplicate:

- protected calibration tasks;
- protected synthesis tasks;
- protected standalone repair tasks;
- RL v1 development tasks;
- another split in RL v2.

Use explicit allowlists for intentionally shared generic vocabulary. Produce a contamination-audit report rather than relying only on task names.

### Sampler-state persistence

The new sampler must serialize:

- RNG seed and state;
- step number;
- phase;
- task exposure counts;
- stratum exposure counts;
- rolling task reward;
- rolling full-pass rate;
- rolling constant-group rate;
- current sampling weights.

A resumed run must produce the same next-task sequence from the same sampler state.

## Phase 2: Build RL v2 datasets

Create new data under:

```text
data/rl/v2/
  canary/
  train/
  dev/
  confirmation/
```

Recommended sizes:

| Split | Tasks | Per category × difficulty cell | Purpose |
|---|---:|---:|---|
| Canary | 12 | 1 | Pipeline validation only |
| Train | 144 | 12 | RL updates |
| Dev | 48 | 4 | Checkpoint selection and early stopping |
| Confirmation | 60 | 5 | One locked final evaluation |

The confirmation set must remain unopened for checkpoint selection. Evaluate it once for the frozen SFT v2 baseline and once for the final selected Phase 2 checkpoint. Do not inspect task-level confirmation failures while training.

### Training-set design

Keep all 12 category × difficulty cells represented.

Within Level 2 and Level 3, include independently generated task families covering:

- nested protocol headers and options;
- bounded parsing;
- VLAN/Q-in-Q behavior;
- encapsulation and decapsulation;
- checksum-sensitive transformations;
- stateful maps;
- LRU and hash maps;
- LPM trie IPv4 and IPv6 behavior;
- token-bucket or counter state;
- redirect and routing semantics.

Do not derive these tasks from `rl_dev_nrf_l3_01` or any protected failure. Generate them from the public project taxonomy and general eBPF/XDP specifications.

For LPM tasks, fixtures should independently test:

- key construction;
- prefix-length boundaries;
- longest-match precedence;
- match and no-match behavior;
- IPv4 or IPv6 byte ordering;
- multiple installed prefixes.

The reward must remain behavioral. Do not expose expected source structure or gold code.

### Fixture requirements

Each task must have:

- positive fixtures;
- negative fixtures;
- boundary fixtures;
- adversarial or malformed-packet fixtures;
- state-transition fixtures when applicable;
- explicit weights;
- exact expected fixture count.

Validate every reference implementation on the VPS before freezing the split. Freeze split hashes before any model evaluation.

## Phase 3: Implement the train-only priority sampler

Replace deterministic round-robin batching with a seeded, stratified sampler.

Do not call the current implementation “uniform random.” Its `get_batch()` selects tasks by deterministic modular indexing.

### Required properties

The sampler must:

- balance application categories;
- enforce a minimum exposure floor for every difficulty;
- use only training-rollout outcomes;
- never consume dev, confirmation, or protected results;
- downweight tasks whose rolling group full-pass rate is consistently high;
- upweight strata with high constant-failure rates only when at least some successful completions exist;
- avoid concentrating on impossible or broken tasks;
- log the probability assigned to every selected task;
- support exact deterministic resume.

### Initial schedule

First reconstruct Phase 1 train-only performance by category, difficulty, and task family. If the raw records support the reported Level 1 saturation, use this initial schedule:

| Training interval | Level 1 | Level 2 | Level 3 |
|---|---:|---:|---:|
| Steps 1–15 | 25% | 40% | 35% |
| Steps 16–60 | 10% | 40% | 50% |

Keep categories uniform within each difficulty unless the train-only audit justifies a predeclared alternative.

Apply a nonzero sampling floor so no category × difficulty cell disappears.

Suggested train-only priority inputs:

```text
difficulty base weight
inverse recent full-pass rate
recent mixed-group rate
minimum exposure correction
task-family coverage correction
```

Do not use raw mean reward alone; partial fixture rewards can make a consistently wrong task appear deceptively strong.

### Group size

Keep `group_size=4` initially for comparability.

If the first 10 Phase 2 steps still produce more than `60%` constant-reward groups, stop that run and perform a separate canary with `group_size=6`. Do not change group size inside an active run without assigning a new run ID and recording the intervention.

## Phase 4: Preserve the reward definition

Keep the Phase 1 reward unchanged:

```text
Structural compliance:          0.02
Compilation pass:               0.08
Kernel-verifier pass:           0.15
Weighted fixture pass fraction: 0.70
Full-suite bonus:               0.05
Maximum:                        1.00
```

Maintain all existing stage gates.

Do not add:

- rewards for recognizing map types;
- regex or AST source-pattern bonuses;
- rewards for a specific LPM key layout;
- token-count penalties;
- source-length penalties;
- BPF instruction-count penalties.

Record the following as non-reward diagnostics:

- completion tokens;
- C source length;
- compiled BPF instruction count;
- stack use when available;
- map types;
- first failure stage;
- fixture-class pass rates.

This preserves causal clarity: Phase 2 changes data selection and optimization, not the objective.

## Phase 5: Phase 2 configuration

Use the following default configuration unless the installed Tinker API requires a documented adjustment:

```text
Starting checkpoint:
  tinker://9461002d-2321-5858-8184-5604f9304283:train:0/weights/final

KL reference:
  tinker://9461002d-2321-5858-8184-5604f9304283:train:0/sampler_weights/final

Base model:
  Qwen/Qwen3-8B

Renderer:
  qwen3_disable_thinking

LoRA rank:
  32

Group size:
  4

Problem groups per step:
  2

Sampling temperature:
  0.8

Maximum completion tokens:
  2048

Initial learning rate:
  3e-6

Final learning rate:
  1e-6

Loss:
  importance_sampling

KL penalty coefficient:
  0.05

Maximum steps:
  60

Save interval:
  5 steps

Dev evaluation interval:
  5 steps

Early-stopping patience:
  3 dev evaluations

Concurrent VPS verifications:
  2

Remove constant-reward groups:
  true
```

### Learning-rate schedule

Inspect the exact installed `tinker` and `tinker-cookbook` APIs.

- If the supported RL configuration provides a real learning-rate scheduler, use a cosine decay from `3e-6` to `1e-6` and serialize the schedule.
- If it does not, use a documented supported alternative.
- Do not silently emulate a scheduler by restarting unrelated training sessions.
- Do not claim optimizer-state continuity unless the resumed checkpoint actually includes it.
- Do not extend to 100 steps merely because it was proposed.

### KL reporting

Enable post-update KL measurement if the pinned API supports it at acceptable cost.

Report:

- exact metric name;
- reference checkpoint;
- pre- or post-update status;
- token weighting;
- per-step mean and maximum;
- coefficient used in the loss.

Do not declare a KL run safe by comparing divergence numerically to the penalty coefficient.

## Phase 6: Baselines and canaries

### Freeze and baseline the new data

Before training:

1. Freeze all RL v2 split manifests and hashes.
2. Run reference implementations on all tasks using the VPS.
3. Evaluate SFT v2 on the 48-task dev set at temperature `0.0`.
4. Evaluate SFT v2 once on the 60-task confirmation set at temperature `0.0`.
5. Seal confirmation task-level results from training-time inspection.
6. Record paired baseline candidates and hashes.

### Sampling-only canary

Run the 12 canary tasks with four samples each:

```text
Tasks:       12
Group size:   4
Rollouts:    48
Temperature: 0.8
Optimizer:   disabled
```

Validate sampler probabilities, empirical rewards, manifests, cleanup, and deterministic reward reconstruction.

### Five-step training canary

Run:

```text
Steps:                    5
Problem groups per step:  2
Group size:               4
Maximum rollouts:         40
Checkpoint interval:      1
```

Do not proceed if:

- any code executes outside the VPS;
- any reward is mock or inferred;
- any infrastructure failure becomes a numeric reward;
- any candidate/result hash mismatches;
- cleanup fails;
- sampler state cannot resume deterministically;
- protected contamination is detected;
- the actual learning-rate behavior differs from the manifest.

## Phase 7: Main Phase 2 run

Run at most 60 optimizer steps.

Evaluate the frozen 48-task dev set every five steps at temperature `0.0`. Use the dev set only for:

- checkpoint selection;
- early stopping;
- detecting obvious regressions.

Primary checkpoint metric:

```text
Dev functional Pass@1
```

Tie-breakers, in order:

1. weighted fixture pass fraction;
2. verifier pass count;
3. compile pass count;
4. lower measured policy divergence;
5. earlier checkpoint.

Do not use average training reward as the primary selection metric.

Stop when:

- no dev functional improvement occurs across three evaluations;
- dev behavior declines while shaped reward rises;
- constant-reward groups exceed `70%` over a 10-step window;
- infrastructure errors exceed `1%`;
- cleanup leaves persistent kernel resources;
- policy divergence becomes unstable relative to its own prior trajectory;
- output compliance falls below `99%`.

If the training API cannot perform real online early stopping, state that limitation before the paid run. Do not describe post-hoc checkpoint selection as early stopping.

## Phase 8: Locked evaluation

After selecting exactly one checkpoint using the 48-task dev set:

1. Freeze its training and sampler checkpoint identifiers.
2. Evaluate it once on the 60-task confirmation set.
3. Compare it with the precomputed SFT v2 confirmation baseline.
4. If the confirmation gate passes, run the frozen protected evaluation once.
5. Do not return to training after seeing confirmation or protected results.

Protected evaluation:

```text
Calibration synthesis:       36 tasks
Private synthesis:          120 tasks
Private standalone repair:  120 tasks
Total:                      276 tasks
```

Use:

```text
Temperature:       0.0
Seed:              42
Samples per task:  1
Maximum tokens:    2048
Execution host:    Hostinger Linux VPS
Verification mode: empirical
```

Produce paired transition matrices and exact two-sided McNemar tests for:

- Phase 2 dev versus SFT v2;
- locked confirmation versus SFT v2;
- calibration versus SFT v2;
- private synthesis versus SFT v2;
- standalone repair versus SFT v2;
- all protected tasks combined.

Use the wording:

> No statistically significant difference was detected.

Do not translate `p > 0.05` into proof of equality or absence of regression.

## Promotion gates

Promote the Phase 2 checkpoint only when every operational gate passes and the locked evidence shows a real improvement.

### Operational gates

- 100% of production rollouts have empirical VPS records.
- No mock, inferred, skipped, or Windows/Tinker execution is present.
- Infrastructure failures are excluded rather than scored.
- Candidate, task, prompt, result, and reward hashes reconcile.
- Fixture counts reconcile.
- Cleanup audit reports no leaked objects.
- Semantic contamination audit passes.
- All split and sampler states are reproducible.
- The selected checkpoint and sampler weights restore successfully.

### Efficacy gates

| Gate | Required result |
|---|---|
| Dev selection | At least `+3/48` tasks over the SFT v2 baseline |
| Locked confirmation | At least `+3/60` tasks, equivalent to `+5.0` percentage points |
| Confirmation paired direction | Fail→pass count must exceed pass→fail count |
| Output compliance | At least `99%` |
| Protected synthesis | Must exceed SFT v2’s `31/120`, not merely remain within a regression allowance |
| Protected calibration | At least `20/36` |
| Protected standalone repair | At least `83/120` |
| Protected combined | At least `137/276` |
| Concentrated regression | No category or difficulty stratum may lose more than two tasks without explicit review |

Statistical significance is reported but is not the sole promotion criterion. Small evaluation sets may lack power; therefore, use paired counts, effect sizes, and the locked confirmation result together.

If any gate fails, retain SFT v2 as the default and archive Phase 2 as an experiment.

## Phase 9: Defer repair RL to a separate experiment

Do not mix repair examples into Phase 2.

After Phase 2 is finalized, design a separate diagnostic-guided repair RL experiment with:

- a newly generated repair training pool;
- exactly one standardized first-failure diagnostic;
- a two-step environment;
- separate synthesis and repair metrics;
- standalone repair and end-to-end Solve@2 evaluation;
- no use of protected failures as training data.

This separation preserves causal interpretation and directly targets the prior `0/15` behavioral-failure recovery result without contaminating the synthesis experiment.

## Suggested repository changes

Prefer extending the existing implementation while keeping Phase 1 artifacts immutable.

```text
training/rl/
  bpf_env.py
  config.py
  dataset.py
  reward.py
  sampler.py
  train_rl.py
  evaluate_rl.py
  run_phase2_evaluations.py
  audit_phase1_records.py
  audit_contamination.py

data/rl/v2/
  canary/
    index.jsonl
    manifest.json
  train/
    index.jsonl
    manifest.json
  dev/
    index.jsonl
    manifest.json
  confirmation/
    index.jsonl
    manifest.json
  task_pool_manifest.json
  contamination_audit.json

runs/tinker/qwen3-8b-bpf-rl-v2/
  config.json
  manifest.json
  sampler_state.json
  metrics.jsonl
  checkpoints.jsonl
  phase1_audit.json
  canary_report.md
  phase2_report.md
  confirmation_comparison.json
  confirmation_comparison.md
  protected_comparison.json
  protected_comparison.md

docs/
  rl-v1-findings-and-phase2-recommendations.md
  rl-v2-design.md
  rl-v2-vps-runbook.md
```

Do not overwrite Phase 1 data, manifests, summaries, or reports except for explicit interpretive corrections in the findings document.

## Required tests

Add or update automated tests for:

- infrastructure error cannot yield a scalar reward;
- fixture-count mismatch invalidates a rollout;
- reward recomputation remains deterministic;
- task-ID contamination;
- prompt and requirements fingerprint contamination;
- task-family overlap across train, dev, confirmation, and protected sets;
- seeded sampler reproducibility;
- sampler resume reproducibility;
- category and difficulty exposure floors;
- sampler never consumes non-training metrics;
- high-pass tasks are downweighted without becoming unreachable;
- impossible or broken tasks are quarantined;
- learning-rate schedule serialization;
- actual learning rate matches the manifest;
- KL metric metadata;
- confirmation split cannot be used for checkpoint selection;
- exact McNemar computation;
- promotion-gate arithmetic;
- mock records rejected from final reports.

Run existing evaluation and verifier tests to ensure Phase 1 behavior remains intact.

## Reproduction requirements

Document exact VPS commands for:

1. pulling the starting commit;
2. auditing the 932 Phase 1 records;
3. correcting and regenerating Phase 1 summaries;
4. generating RL v2 tasks;
5. validating references and fixtures;
6. running semantic contamination checks;
7. freezing split hashes;
8. running SFT v2 dev and confirmation baselines;
9. running the 48-rollout sampling canary;
10. running the five-step training canary;
11. launching Phase 2;
12. resuming Phase 2 with sampler state;
13. evaluating checkpoints on dev;
14. selecting the checkpoint deterministically;
15. running the locked confirmation evaluation;
16. running the protected evaluation;
17. recomputing rewards from raw records;
18. auditing cleanup and empirical provenance.

## Acceptance criteria

The handoff is complete only when:

- [ ] The latest `main` commit and worktree state are recorded.
- [ ] Phase 1’s 932 claimed rollouts are audited or missing records are disclosed.
- [ ] Statistical and KL interpretations in the Phase 1 report are corrected.
- [ ] SFT v2 remains the initialization and KL reference.
- [ ] RL Phase 1 `000035` remains archived and unpromoted.
- [ ] Infrastructure failures cannot return numeric rewards.
- [ ] Semantic contamination checks go beyond task IDs.
- [ ] RL v2 canary, train, dev, and confirmation splits are frozen and hashed.
- [ ] The confirmation set is not used for training or checkpoint selection.
- [ ] The train-only sampler is seeded, stratified, logged, and resumable.
- [ ] Phase 2 retains the Phase 1 reward definition.
- [ ] No map-structure reward or length penalty is introduced.
- [ ] No repair co-training occurs.
- [ ] All generated code executes only on the VPS.
- [ ] All production rewards are empirical.
- [ ] The sampling and training canaries pass.
- [ ] The main run respects its declared learning-rate behavior.
- [ ] Checkpoint selection uses only RL v2 dev.
- [ ] Confirmation is evaluated once after selection.
- [ ] Protected evaluation is run only after confirmation passes.
- [ ] Paired transition and McNemar analyses are generated.
- [ ] Promotion occurs only if every operational and efficacy gate passes.
- [ ] SFT v2 remains recoverable and active if Phase 2 fails.

## Required final response

When finished, report:

1. Branch and commit SHA.
2. Files changed.
3. Phase 1 audit result and number of validated raw records.
4. Corrections made to the Phase 1 report.
5. RL v2 task counts and split hashes.
6. Semantic contamination-audit result.
7. Sampler design and realized exposure by category and difficulty.
8. Reward definition and confirmation that it was unchanged.
9. Exact learning-rate behavior.
10. KL metric definition and observed trajectory.
11. Sampling-only canary result.
12. Five-step canary result.
13. Main-run steps, rollouts, constant-group rate, and infrastructure failures.
14. SFT v2 and Phase 2 dev results.
15. Selected checkpoint identifiers.
16. Locked confirmation paired results.
17. Protected paired results and exact McNemar values.
18. Cleanup and provenance audit.
19. Promotion decision.
20. Remaining limitations or blockers.

Do not claim Phase 2 succeeded if its selected checkpoint was chosen using confirmation or protected data, if any production reward lacks a valid VPS record, or if generated BPF code executed anywhere other than the VPS.

