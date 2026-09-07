# Handoff: Implement Qwen3-8B BPF RLVR Phase

## Mission

Implement and run the first reinforcement-learning phase for the BPF fine-tuning project.

Train Qwen3-8B SFT v2 using verifiable rewards from actual eBPF execution. Every generated candidate must be compiled, loaded through the Linux kernel verifier, and behaviorally tested with `BPF_PROG_TEST_RUN` on the Hostinger Linux VPS.

The architecture must enforce this boundary:

```text
Tinker:
- model sampling
- forward/backward passes
- optimizer updates
- checkpoint storage

Hostinger VPS:
- RL controller
- prompt and rollout orchestration
- candidate persistence
- Clang BPF compilation
- Linux kernel verifier loading
- BPF_PROG_TEST_RUN execution
- cleanup
- reward calculation
- empirical logs
```

Generated code must never execute:

- on Tinker servers;
- on the user’s Windows machine;
- in a mock verifier during a production RL run.

Start with single-turn synthesis RLVR. Do not implement multi-turn synthesis→diagnostic→repair RL until the single-turn reward environment is demonstrably reliable.

## Repository and starting point

Repository:

```text
RavindraTarunokusumo/BPF-FT-Project
```

Expected starting commit:

```text
a860c643e03e920e555ccdc69927327ebd9b585b
```

Before editing:

1. Pull the latest `main`.
2. Read `AGENTS.md` and all relevant training and evaluation documentation.
3. Inspect the current worktree and preserve unrelated changes.
4. Confirm that the latest SFT evaluation artifacts remain intact.
5. Record the exact repository commit used to start the RL run.

### SFT v2 initialization checkpoint

RL training requires the training-state checkpoint, not the sampler-only checkpoint:

```text
tinker://9461002d-2321-5858-8184-5604f9304283:train:0/weights/final
```

Use the sampler checkpoint only for evaluation or inference:

```text
tinker://9461002d-2321-5858-8184-5604f9304283:train:0/sampler_weights/final
```

Configuration inherited from SFT v2:

```text
Base model: Qwen/Qwen3-8B
Renderer: qwen3_disable_thinking
LoRA rank: 32
Maximum completion tokens: 2048
```

The KL reference must be the frozen SFT v2 checkpoint, not the original Qwen3-8B base model.

## Confirmed SFT v2 baseline

Use these results as the frozen pre-RL baseline:

```text
Calibration synthesis Pass@1:       21/36  = 58.3%
Private synthesis Pass@1:           31/120 = 25.8%
Private synthesis compilation:      65/120 = 54.2%
Private synthesis verifier pass:    46/120 = 38.3%

Standalone repair Repair@1:         85/120 = 70.8%
Standalone repair compilation:     110/120 = 91.7%
Standalone repair verifier pass:   106/120 = 88.3%

Controlled synthesis Repair@1:      12/89  = 13.5%
End-to-end synthesis Solve@2:       43/120 = 35.8%

Global functional Pass@1:          137/276 = 49.6%
```

The greatest opportunity is synthesis. Controlled repair recovered only:

```text
Compilation-stage failures: 11/55
Verifier-stage failures:      1/19
Behavioral-stage failures:    0/15
```

Therefore, RL v1 should optimize one-shot synthesis correctness, with behavioral execution as the dominant reward signal.

## Technical approach

Use Tinker’s standard RL abstractions:

```text
RLDataset
  -> EnvGroupBuilder
  -> async Env
  -> grouped rollouts
  -> VPS empirical reward
  -> group-relative advantages
  -> optimizer update
```

Tinker’s RL cookbook supports environment-defined rewards and group-relative training. Constant-reward groups produce no useful advantage and should be excluded. See the official [RL architecture](https://tinker-docs.thinkingmachines.ai/cookbook/rl/), [first RL tutorial](https://tinker-docs.thinkingmachines.ai/tutorials/basics/first-rl/), and [configuration-based RL loop](https://tinker-docs.thinkingmachines.ai/tutorials/cookbook-abstractions/rl-with-config/).

Implement a custom asynchronous environment. Do not use a synchronous `ProblemEnv.check_answer()` path for kernel verification because compilation, loading, packet testing, and cleanup are slow external operations.

The controller process itself must run on the VPS and call the verifier harness locally. Do not expose a public reward HTTP endpoint unless the existing project architecture makes that unavoidable.

## Phase 1: Audit and pin the RL runtime

On the VPS:

1. Confirm Python, Tinker SDK, and `tinker-cookbook` versions.
2. Pin the exact versions used for the run.
3. Verify that the VPS can authenticate with Tinker using an environment-provided credential.
4. Confirm the SFT v2 training-state checkpoint can initialize an RL training client.
5. Confirm the renderer produces the same prompt format used during SFT.
6. Record all versions in the run manifest.

Do not commit credentials or print them in logs.

The repository currently specifies minimum package versions. The RL manifest must record the exact installed versions.

## Phase 2: Build the VPS kernel reward executor

Create a narrow verifier adapter around the already-hardened empirical verification harness.

A suitable interface is:

```python
async def evaluate_candidate(
    task: RLTask,
    source: str,
    rollout_id: str,
) -> VerificationResult:
    ...
```

The returned result must distinguish:

```text
output compliance
compilation attempted
compilation passed
verifier attempted
verifier passed
behavioral execution attempted
fixtures expected
fixtures executed
fixtures passed
cleanup passed
infrastructure error
timeout stage
raw log paths
source SHA-256
task SHA-256
```

### Required execution order

For every generated candidate:

1. Save the exact completion to a unique per-rollout directory.
2. Calculate and record its SHA-256.
3. Validate structural output compliance.
4. Compile it with the project’s exact Clang BPF command.
5. If compilation succeeds, load it through the actual Linux kernel verifier.
6. If loading succeeds, execute the complete fixture suite with `BPF_PROG_TEST_RUN`.
7. Perform cleanup in a `finally` path.
8. Persist raw stdout, stderr, verifier logs, fixture results, timing, and cleanup status.
9. Calculate the reward only after the empirical record has been written successfully.

### Isolation requirements

Generated source is untrusted.

- Run the RL controller under a dedicated unprivileged account.
- Compile under an unprivileged account or isolated container.
- Permit privileged BPF operations only through the narrow existing verifier runner.
- Never invoke generated text through a shell.
- Use argument arrays and `shell=False`.
- Use fixed compiler and loader commands.
- Restrict available include paths.
- Disable network access for candidate execution.
- Apply CPU, memory, process, file-size, and wall-clock limits.
- Limit captured stdout and stderr.
- Use an isolated temporary directory for every rollout.
- Clean BPF objects, pins, maps, namespaces, temporary interfaces, and files.
- Treat cleanup failure as an infrastructure failure.
- Prefer a dedicated or disposable VPS snapshot for RL execution.

Set verifier concurrency explicitly. Start with:

```text
maximum concurrent candidates: 2
```

Increase it only after measuring the VPS without causing timeouts or kernel-resource contention.

### Fail-closed semantics

The following are infrastructure failures, not model failures:

- compiler unavailable;
- loader unavailable;
- test harness unavailable;
- missing fixture;
- fixture-count mismatch;
- incomplete or corrupt result record;
- reward/result hash mismatch;
- VPS resource exhaustion;
- unexpected timeout caused by infrastructure;
- cleanup failure.

An infrastructure failure must:

1. produce no training reward;
2. be retried once when safe;
3. invalidate the rollout if the retry fails;
4. pause the run after repeated failures.

Never convert an infrastructure error into reward `0.0`.

## Phase 3: Construct a new RL task pool

Do not use any protected evaluation task as RL training or development data.

Explicitly exclude:

```text
calibration-synthesis
benchmark-synthesis-120
benchmark-repair-120
controlled synthesis Repair@1 tasks
hidden fixtures
gold solutions
private benchmark diagnostics
```

Create new task instances based on the project’s training taxonomy:

```text
Application categories:
- packet_inspection_telemetry
- network_routing_forwarding
- packet_filtering_security
- protocol_transformation

Difficulty:
- level_1
- level_2
- level_3
```

### Initial pool

Create:

```text
Integration canary: 12 tasks
Pilot training:     96 tasks
Pilot development:  24 tasks
```

Use one canary task for each category × difficulty cell. For pilot data, keep the same cells balanced:

```text
Training:    8 tasks per category × difficulty cell
Development: 2 tasks per category × difficulty cell
```

Training and development tasks must be task-disjoint, not merely prompt-reworded copies.

Each task must include:

- stable task ID;
- category and difficulty;
- complete public prompt;
- program type and expected attachment mode;
- fixture manifest;
- fixture weights;
- expected fixture count;
- timeout policy;
- task SHA-256;
- provenance and generator version.

Reference implementations may be used to validate new tasks and fixtures before RL begins, but reference source must never be placed in prompts, rollouts, rewards, or model-visible diagnostics.

Before training:

1. Run each reference implementation on the VPS.
2. Confirm compilation and verifier acceptance.
3. Confirm every fixture executes.
4. Confirm positive and negative fixtures discriminate expected behavior.
5. Reject tasks with ambiguous, trivial, or unstable reward signals.
6. Produce an aggregate task-pool hash.

## Phase 4: Implement the reward function

Behavioral correctness must dominate the reward.

Use the following initial bounded reward:

```text
Structural output compliance: 0.02
Successful BPF compilation:   0.08
Kernel verifier acceptance:   0.15
Weighted fixture pass rate:   0.70
Complete-suite bonus:         0.05
Maximum reward:               1.00
```

Equivalent definition:

```text
reward =
    0.02 * compliance
  + 0.08 * compile_pass
  + 0.15 * verifier_pass
  + 0.70 * weighted_fixture_fraction
  + 0.05 * full_behavioral_pass
```

Apply stage gates:

- compilation credit requires an actual successful compile;
- verifier credit requires compilation and a successful real kernel load;
- behavioral credit requires verifier acceptance;
- the full-suite bonus requires every required fixture to pass;
- missing or skipped fixtures cannot receive partial credit;
- an empty fixture run receives no behavioral credit.

Fixture weighting must prevent trivial implementations such as unconditional `XDP_PASS` or unconditional `XDP_DROP` from earning high rewards.

Each task should identify:

```text
core positive fixtures
core negative fixtures
boundary fixtures
adversarial fixtures
state-transition fixtures, when applicable
```

A candidate is functionally passed only if all required fixtures pass, regardless of its shaped reward.

Persist both:

```text
scalar training reward
individual reward components
```

Add tests for:

- non-code output;
- valid-looking source that does not compile;
- compilation success with verifier rejection;
- verifier success with zero fixtures executed;
- partial behavioral success;
- trivial pass-all and drop-all programs;
- complete functional success;
- timeout;
- fixture-count mismatch;
- infrastructure error;
- cleanup failure;
- deterministic reward recomputation from a raw record.

## Phase 5: Implement the Tinker RL environment

Implement a single-turn async environment:

```text
initial_observation:
    complete BPF synthesis task

model action:
    complete self-contained XDP C source

environment step:
    persist candidate
    call VPS verifier
    compute reward
    emit metrics
    finish episode
```

The prompt must request:

```text
Corrected, complete, self-contained XDP C source only.
No Markdown fences, prose, or thinking blocks.
```

For synthesis prompts, remove “Corrected” if no faulty source is provided.

The environment must:

- preserve the exact generated token sequence;
- preserve the rendered completion;
- reject multiple or missing completions;
- assign an idempotent rollout ID;
- prevent duplicate reward submission;
- associate each reward with candidate, task, prompt-template, and repository hashes;
- return structured task-level metrics;
- omit invalid infrastructure rollouts from training data.

Use groups of independent completions for the same task so the trainer can calculate group-relative advantages. This follows Tinker’s documented grouped RL pattern.

## Phase 6: Initial RL configuration

Start conservatively from SFT v2.

```text
load_checkpoint_path:
  tinker://9461002d-2321-5858-8184-5604f9304283:train:0/weights/final

base model:
  Qwen/Qwen3-8B

renderer:
  qwen3_disable_thinking

LoRA rank:
  32

group size:
  4

sampling temperature:
  0.8

maximum tokens:
  2048

learning rate:
  5e-6

loss:
  importance_sampling

KL penalty coefficient:
  0.05

KL reference:
  SFT v2 training-state checkpoint

remove constant-reward groups:
  true

problem groups per optimizer step:
  2

concurrent VPS verifications:
  2
```

Tinker recommends grouped exploration and documents a typical initial KL coefficient of `0.05`; its RL guidance also explains that KL regularization helps limit reward hacking, forgetting, and mode collapse. See [RL hyperparameters](https://tinker-docs.thinkingmachines.ai/tutorials/advanced/rl-hyperparams/) and [supported losses](https://tinker-docs.thinkingmachines.ai/tinker/losses/).

Do not use temperature `0.0` for RL sampling. Deterministic temperature `0.0` remains appropriate for benchmark evaluation.

Make all hyperparameters configurable without editing source.

## Phase 7: Sampling-only integration run

Before any optimizer update:

1. Initialize sampling from SFT v2.
2. Sample a four-completion group for a canary task.
3. Save all four exact candidates.
4. Execute all candidates on the VPS.
5. Recompute rewards independently from their raw records.
6. Confirm source and task hashes.
7. Confirm no candidate executed outside the VPS.
8. Confirm all cleanup completed.
9. Confirm no optimizer update occurred.

Repeat across the 12 canary tasks.

Do not begin RL training unless all canary records are complete and empirical.

## Phase 8: Canary RL run

Run a small training canary:

```text
maximum optimizer steps: 5
group size:              4
problem groups/step:     2
save every:              1 step
development evaluation: before and after canary
```

This produces at most 40 training rollouts before retry handling.

Pause immediately if any of the following occurs:

- a candidate is not executed on the VPS;
- an empirical record is missing;
- a result hash does not match its candidate;
- infrastructure errors exceed 1%;
- cleanup leaves persistent BPF resources;
- constant-reward groups exceed 70%;
- output compliance drops materially;
- rewards become dominated by compilation without behavioral improvement;
- KL or loss becomes unstable;
- checkpoints cannot be reproduced from the manifest.

Produce a canary report before expanding the run.

## Phase 9: Pilot RL run

If the canary passes, run the balanced 96-task pilot pool.

Recommended initial limit:

```text
maximum optimizer steps: 50
group size:              4
problem groups/step:     2
save every:              5 steps
development evaluation: every 5 steps
```

Select checkpoints using only the task-disjoint RL development set.

The primary selection metric is:

```text
development functional Pass@1 at temperature 0.0
```

Secondary metrics:

- behavioral fixture pass rate;
- kernel-verifier pass rate;
- compilation rate;
- output compliance;
- average empirical reward;
- constant-reward group rate;
- KL;
- verifier throughput;
- infrastructure failure rate.

Do not select checkpoints using the protected 276-task evaluation suite.

Stop early if development functional correctness has not improved across three consecutive evaluations or if behavioral correctness declines while shaped reward rises.

## Phase 10: Frozen post-RL evaluation

After selecting the best checkpoint using the RL development set, evaluate it once against the frozen existing suites:

```text
calibration-synthesis
benchmark-synthesis-120
benchmark-repair-120
controlled synthesis Repair@1 workflow, if resources permit
```

Use:

```text
temperature: 0.0
seed: 42
samples per task: 1
max tokens: 2048
verification: real VPS only
```

Do not alter the protected tasks, fixtures, or expected outputs.

Compare the selected RL checkpoint against SFT v2 using matched task transitions and an exact two-sided McNemar test.

Report:

- fail→fail;
- fail→pass;
- pass→fail;
- pass→pass;
- exact McNemar p-value;
- compilation changes;
- verifier changes;
- functional changes;
- regressions by category and difficulty.

The frozen suite may validate the final selected model but must not influence optimizer updates or checkpoint selection.

## Advancement gates

Promote the RL checkpoint only if all of the following hold:

- all production rewards were computed empirically on the VPS;
- no protected evaluation task entered the RL dataset;
- infrastructure failures were excluded from training rewards;
- cleanup completed successfully;
- development functional Pass@1 improved by at least 5 percentage points;
- development output compliance remains at least 99%;
- development compilation and verifier rates do not regress by more than 2 percentage points;
- protected synthesis does not regress by more than three tasks from `31/120`;
- protected standalone repair does not regress by more than five tasks from `85/120`;
- paired results do not reveal a concentrated catastrophic regression;
- the final checkpoint and its sampler weights can be restored successfully.

If the gates fail, retain SFT v2 as the project’s final checkpoint and report the RL run as an experiment.

Do not hide an unsuccessful RL result.

## Future phase: diagnostic-guided repair RL

Do not mix repair RL into the initial synthesis RL run.

After RL v1 is complete, a separate RL v2 experiment may use a two-step environment:

```text
Step 1:
model synthesizes candidate

VPS:
compile, load, and execute
return one standardized first-failure diagnostic

Step 2:
model submits one corrected candidate

VPS:
repeat complete empirical verification
```

This later phase should target:

- low controlled Repair@1 recovery;
- verifier-failure recovery;
- the current `0/15` behavioral-failure recovery result;
- end-to-end Solve@2.

The synthesis and repair rewards must remain separately attributable.

## Suggested repository structure

Follow existing repository conventions where possible. A suitable layout is:

```text
training/rl/
  bpf_env.py
  dataset.py
  reward.py
  kernel_executor.py
  train_rl.py
  evaluate_rl.py
  config.py

data/rl/v1/
  canary/
    index.jsonl
    manifest.json
  train/
    index.jsonl
    manifest.json
  dev/
    index.jsonl
    manifest.json

runs/tinker/qwen3-8b-bpf-rl-v1/
  config.json
  manifest.json
  metrics.jsonl
  checkpoints.jsonl
  reward_records.jsonl
  verifier_records/
  canary_report.md
  pilot_report.md

docs/
  rl-v1-design.md
  rl-v1-vps-runbook.md
```

Do not commit secrets, Tinker credentials, SSH credentials, transient BPF pins, or unrestricted raw environment dumps.

Empirical candidate and verifier records should be committed if consistent with the project’s existing artifact policy.

## Required tests

Add automated tests covering:

- reward components and gates;
- infrastructure error versus model failure;
- missing and duplicate rollout IDs;
- source-hash mismatch;
- task-hash mismatch;
- fixture-count mismatch;
- empty fixture run;
- timeout handling;
- cleanup failure;
- constant-reward group filtering;
- protected-task exclusion;
- training/development task overlap;
- deterministic task sampling;
- deterministic reward reconstruction;
- retry without duplicate reward submission;
- mock verifier rejection in production mode.

Add VPS integration tests for:

- known successful BPF program;
- compilation failure;
- verifier rejection;
- partial behavioral failure;
- complete behavioral pass;
- process timeout;
- cleanup verification.

## Reproduction requirements

Document exact commands for:

1. provisioning the VPS runtime;
2. installing pinned dependencies;
3. authenticating the VPS to Tinker;
4. validating the RL task pool;
5. running verifier integration tests;
6. running the sampling-only canary;
7. running the five-step RL canary;
8. resuming from a checkpoint;
9. running the pilot;
10. evaluating a selected checkpoint;
11. recreating rewards from raw records;
12. auditing for protected benchmark contamination.

Every run manifest must include:

- repository commit;
- dirty-worktree status;
- starting checkpoint;
- saved checkpoint IDs;
- base model;
- renderer;
- sampling configuration;
- optimizer configuration;
- KL configuration;
- package versions;
- VPS kernel and toolchain;
- task-pool hash;
- prompt-template hash;
- candidate-set hash;
- reward-function version;
- timestamps;
- aborted or retried rollout IDs.

## Acceptance criteria

The implementation is complete only when:

- [ ] The RL controller runs on the Hostinger VPS.
- [ ] Tinker is used only for sampling, training operations, and checkpoint storage.
- [ ] Generated BPF code never executes on Tinker servers or Windows.
- [ ] The SFT v2 training-state checkpoint initializes successfully.
- [ ] The KL reference is frozen SFT v2.
- [ ] The reward executor uses real Clang, the Linux verifier, and `BPF_PROG_TEST_RUN`.
- [ ] Infrastructure failures cannot become model rewards.
- [ ] Generated code is executed with strict isolation and cleanup.
- [ ] Canary, training, and development tasks are distinct from protected benchmarks.
- [ ] Task and fixture manifests are hashed.
- [ ] Reward reconstruction is deterministic.
- [ ] The 12-task sampling-only canary passes.
- [ ] The five-step RL canary completes without provenance or cleanup failures.
- [ ] The pilot uses balanced task groups.
- [ ] Checkpoint selection uses only the RL development set.
- [ ] Final protected evaluation runs empirically on the VPS.
- [ ] Paired regression analysis is produced.
- [ ] All commands and versions are documented.
- [ ] SFT v2 remains recoverable if RL fails its advancement gates.

## Required final response

When finished, report:

1. Commit SHA and branch.
2. Files changed.
3. Exact VPS environment and toolchain.
4. Exact Tinker and cookbook versions.
5. Starting checkpoint and KL-reference checkpoint.
6. RL task counts and task-pool hashes.
7. Reward definition.
8. Confirmation that every production reward was computed on the VPS.
9. Sampling-only canary result.
10. Five-step canary result.
11. Pilot steps and rollout count.
12. Infrastructure failures and retries.
13. Cleanup audit result.
14. Development metrics before and after RL.
15. Selected checkpoint.
16. Frozen benchmark results versus SFT v2.
17. Paired transitions and McNemar results.
18. Whether the RL checkpoint passed the advancement gates.
19. Remaining limitations or blockers.

Do not claim the RL phase succeeded if any production reward was mocked, inferred, executed outside the VPS, missing its raw record, or associated with a mismatched candidate hash.
