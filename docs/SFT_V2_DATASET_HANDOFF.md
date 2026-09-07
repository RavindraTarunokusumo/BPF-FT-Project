# Handoff Brief: Generate the Qwen3-8B SFT v2 Dataset

## Mission

Build, validate, freeze, and document the SFT v2 dataset for the BPF-FT project. The new dataset must improve out-of-distribution XDP/eBPF synthesis—especially unfamiliar protocols, nested parsing, routing, maps, and checksum logic—while preserving the strong diagnostic-repair capability learned in SFT v1.

Do not train a model as part of this task. Do not modify or regenerate any evaluation benchmark. The output of this task is a reproducible, frozen dataset and its validation reports.

## Evidence from the completed evaluation

Use the following aggregate findings as the design basis:

- SFT v1 calibration synthesis: 20/36 functional Pass@1 (55.6%).
- SFT v1 calibration Repair@1: 16/16 recoveries; post-repair total 36/36.
- Private held-out synthesis: 0/120 functional Pass@1, despite 49/120 compiling and 31/120 passing the kernel verifier.
- Private held-out repair: 75/120 functional Pass@1 (62.5%).
- Private repair by category:
  - packet inspection and telemetry: 80.0%
  - packet filtering and security: 70.0%
  - protocol transformation: 53.3%
  - network routing and forwarding: 46.7%
- Recurring synthesis weaknesses: variable/nested header offsets, maps and flags, checksum deltas, unfamiliar encapsulations, stateful mechanics, FIB routing, and exact behavioral semantics.

The central diagnosis is: **v1 learned output discipline and diagnostic repair, but did not generalize sufficiently to novel synthesis families.** SFT v2 must therefore increase semantic and structural diversity rather than produce more constant-swapped copies of existing templates.

## Non-negotiable benchmark isolation

Treat all existing evaluation artifacts as protected test material:

- `data/benchmark/synthesis/**`
- `data/benchmark/repair/**`
- all 240 private benchmark task IDs, prompts, faulty programs, diagnostics, reference programs, and fixtures
- `data/calibration/**`, which remains the development/calibration benchmark

Rules:

1. Do not copy, paraphrase, mutate, repair, or train on any protected benchmark task.
2. Do not use benchmark-generated candidates, diagnostics, reference code, test names, expected packet outputs, or fixtures as SFT examples.
3. Do not generate “new” examples by changing constants, addresses, ports, identifiers, or protocol names in a benchmark task.
4. A leakage checker may read protected artifacts only to calculate IDs, hashes, and similarity flags. Benchmark contents must not be passed back into the generation or repair agents.
5. Preserve the private benchmarks byte-for-byte.
6. Record benchmark-exclusion hashes in the v2 freeze manifest.

If an example is potentially derived from a protected task, reject it. Do not attempt to sanitize it.

## Dataset architecture

Create two layers:

### 1. New v2 delta

Target **1,200 new examples**:

- **720 synthesis examples** based on 720 unique task IDs
- **480 diagnostic-repair examples**, each associated with a new v2 synthesis task

Every synthesis example must be a genuinely distinct task instance. Parameter changes alone do not make a distinct task.

Repair-failure targets:

| Failure type | Target examples | Purpose |
|---|---:|---|
| Compilation error | 120 | Kernel C types, headers, maps, helpers, structs, declarations |
| Kernel verifier rejection | 160 | Bounds, pointer validity, stack, loops, map/value safety |
| Behavioral logic bug | 200 | Offsets, endianness, checksums, state transitions, exact policy semantics |

Use actual diagnostics produced by Clang, libbpf/kernel verification, or behavioral fixtures. Never fabricate diagnostic text.

### 2. Cumulative v2 training corpus

Preserve `data/sft/frozen/v1/**` unchanged. Select a deterministic, balanced **400-example replay subset** from v1 to reduce catastrophic forgetting:

- 200 synthesis examples
- 200 repair examples
- balanced across application categories and difficulty levels
- no calibration or private-benchmark material

The cumulative corpus should therefore contain **1,600 examples before validation holdouts**: 1,200 new examples plus 400 v1 replay examples. Keep `v2_delta.jsonl` and the replay manifest separate so the exact composition remains auditable.

## New synthesis coverage

Balance the 720 new synthesis tasks across the four existing application categories:

| Category | Target |
|---|---:|
| `packet_filtering_security` | 180 |
| `network_routing_forwarding` | 180 |
| `packet_inspection_telemetry` | 180 |
| `protocol_transformation` | 180 |

Balance difficulty globally:

- Level 1: 240 tasks
- Level 2: 240 tasks
- Level 3: 240 tasks

Cover the following capability families, without reproducing benchmark tasks:

- VXLAN, GENEVE, GRE, and GTP-U parsing and policy logic
- IPv6 and SRv6 parsing, including bounded extension-header handling
- single VLAN, Q-in-Q, and mixed tagged/untagged paths
- nested outer/inner IPv4 and IPv6 parsing
- variable IPv4 IHL, TCP data offset, and protocol option lengths
- FIB lookup, longest-prefix policy, next-hop selection, ECMP, redirect, and fallback behavior
- token-bucket and quota enforcement with verifier-safe map state
- DNS metadata and tunneling indicators without copying private benchmark specifications
- flow keys, telemetry aggregation, per-CPU maps, LRU maps, LPM trie maps, and safe key layouts
- stateless and stateful NAT/port transformations
- incremental IPv4, TCP, UDP, and ICMP checksum updates
- malformed, truncated, fragmented, non-matching, and boundary-value packets

Every semantic family must contain varied control flow, prompt language, packet layouts, map designs, and expected actions. Do not let a single template family exceed 5% of the v2 delta.

## Example formats

Retain the v1 conversational schema and metadata fields:

- `example_id`
- `task_id`
- `category`
- `difficulty`
- `template_family`
- `example_type`
- `messages`

Add provenance fields outside `messages`:

- `dataset_version: "v2"`
- `source_kind: "new_v2" | "v1_replay"`
- `semantic_family`
- `generator_id`
- `generation_attempt`
- `gold_source_sha256`
- `task_spec_sha256`
- `fixture_manifest_sha256`
- for repairs: `fault_class`, `fault_injection_id`, `diagnostic_sha256`, and `parent_synthesis_task_id`

### Synthesis example

- System message: expert Linux kernel eBPF/XDP programmer.
- User message: complete task specification, required interfaces, map contracts, malformed-packet policy, and output requirements.
- Assistant message: only complete, self-contained C source.

### Repair example

- System message: diagnostic-guided eBPF/XDP repair expert.
- User message: original specification, faulty complete source, and exact diagnostic output.
- Assistant message: corrected complete C source only.

Do not include markdown fences, prose, hidden fixtures, chain-of-thought, or `<think>` blocks in assistant targets. Maintain compatibility with `qwen3_disable_thinking`.

## Task and fixture construction requirements

Each new synthesis task must have:

- `task.json`
- `tests.json`
- binary packet fixtures or deterministic fixture-generation inputs
- a gold `program.c`
- a manifest containing hashes and toolchain information

Tests must include:

1. Positive matching packets.
2. Negative non-matching packets.
3. Truncated input at every material header boundary.
4. Boundary values for lengths, ports, prefixes, flags, and counters.
5. Endianness-sensitive cases.
6. Stateful sequences where the task uses maps or rate state.
7. At least one adversarial case that distinguishes a superficial implementation from the intended behavior.

For tasks requiring maps, define and validate map initialization explicitly. For FIB or redirect tasks, define the test context and permitted helper outcomes. Reference programs must pass under the same Linux 6.8 / Clang 18 environment used for evaluation.

## Gold-code quality gate

No row may enter the dataset until its assistant target:

1. Is valid pure C output.
2. Compiles with the project’s exact Clang BPF command.
3. Loads successfully through the real kernel verifier.
4. Passes every behavioral fixture.
5. Leaves no residual BPF pins, namespaces, interfaces, or maps.
6. Produces the same result in a clean rerun.

Fail closed. A timeout, skipped test, missing dependency, unavailable helper, empty fixture run, or cleanup failure is not a pass.

For repair rows, additionally verify that:

- the faulty source fails at the declared stage;
- the stored diagnostic is generated from that exact faulty source;
- the correction fixes the specified fault;
- the corrected source passes compilation, verification, and all behavior tests;
- the faulty and corrected programs are not identical after normalization.

## Diversity and duplication controls

Implement automated checks for:

- exact duplicate messages, prompts, tasks, and assistant code;
- normalized duplicates after removing task IDs, symbol names, comments, numeric constants, addresses, and ports;
- near-duplicate prompts using token similarity;
- near-duplicate code using token or AST fingerprints;
- semantic-family concentration;
- repeated fixture structures;
- v1 overlap;
- calibration and private-benchmark overlap.

Acceptance thresholds:

- zero exact duplicates;
- zero train/validation task overlap;
- zero protected benchmark task-ID or source-hash overlap;
- no normalized prompt/code cluster containing more than 8 examples without manual justification;
- no semantic family above 5% of the v2 delta;
- at least 95% unique normalized user instructions;
- all repair and synthesis variants for the same task remain in the same split.

Similarity flags are review queues, not automatic evidence that a near match is safe.

## Split strategy

Do not repeat the v1 strategy of stratifying every template family into both train and validation only. Produce two validation views:

1. **In-domain validation**: task-disjoint examples from semantic families represented in training.
2. **Family-held-out validation**: complete semantic/template families absent from training.

Recommended split of the cumulative corpus:

- Training: approximately 80%
- In-domain validation: approximately 10%
- Family-held-out validation: approximately 10%

Split by task group so synthesis and repair examples derived from one task cannot cross splits. Balance categories, difficulty, and example types as closely as the family holdout permits. The family-held-out set is the main validation signal for synthesis generalization; report its metrics separately from ordinary validation NLL.

## Required implementation outputs

Create or update reproducible tooling and produce:

```text
data/sft/v2/
  source/
  v2_delta.jsonl
  v1_replay_manifest.json
  quality_report.json
  leakage_report.json
  data_card.md

data/sft/frozen/v2/
  train.jsonl
  validation_in_domain.jsonl
  validation_family_heldout.jsonl
  freeze_manifest.json
  split_report.md

training/
  build_sft_v2.py
  validate_sft_v2.py
  prepare_sft_v2_splits.py
```

Use deterministic seeds and stable sorting. The freeze manifest must record source commit, source hashes, split hashes, scripts and their hashes, configuration fingerprint, category/difficulty/family distributions, replay membership, excluded benchmark hashes, renderer, base model, maximum sequence length, toolchain, and validation-host kernel version.

## Acceptance criteria

The handoff is complete only when:

- exactly 1,200 new verified examples exist with the requested 720/480 synthesis-repair composition;
- the repair fault distribution matches 120 compilation / 160 verifier / 200 behavioral examples;
- the 400-example v1 replay selection is deterministic and balanced;
- every new gold completion passes compile, kernel-verifier, and behavioral tests twice;
- all reference programs and fixtures are reproducible on a clean verifier host;
- dataset schema and hashes validate;
- duplicate and leakage checks pass;
- train, in-domain validation, and family-held-out validation are task-disjoint;
- complete families are absent from training for the family-held-out set;
- all frozen file hashes match the manifest;
- rerunning the build with the same inputs and seed is byte-reproducible;
- the data card clearly documents intended use, limitations, distributions, contamination controls, and known unsupported kernel/helper behavior.

## Execution order

1. Audit the current dataset builders, validators, v1 freeze manifest, and verifier interfaces.
2. Build a protected-ID/hash denylist without exposing benchmark content to generation agents.
3. Define the v2 semantic-family taxonomy and exact quota matrix.
4. Generate task specifications and fixtures.
5. Write and verify gold synthesis programs.
6. Create real faulty variants, collect diagnostics, and verify corrected repair targets.
7. Run duplication, semantic-diversity, and benchmark-leakage checks.
8. Select the deterministic v1 replay subset.
9. Create the two validation views and training split.
10. Freeze artifacts, generate reports, and rerun all validators from a clean checkout.

## Explicitly out of scope

- Running SFT v2 training
- Modifying the 240 private benchmarks or the calibration benchmark
- Using private benchmark failures as training examples
- Generating Pass@k results
- Enabling chain-of-thought targets
- DPO, RLHF, or verifier-reward training
- Claiming expected benchmark improvement before the frozen SFT v2 model is evaluated

At completion, provide a concise summary of counts, distributions, hashes, quality-gate results, held-out families, rejected examples and reasons, and exact commands for reproducing the frozen dataset.
