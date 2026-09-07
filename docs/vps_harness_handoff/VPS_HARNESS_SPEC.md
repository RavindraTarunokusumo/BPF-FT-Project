# BPF-Guardian VPS Validation Harness Specification

## 1. Purpose

The harness is the sole authority that labels generated XDP/eBPF candidates.
It converts an immutable candidate source file plus an executable test contract
into an immutable structured result.

```text
task.json + tests.json + manifest.json + program.c
    -> schema and policy checks
    -> Clang BPF compilation
    -> kernel verifier load
    -> declared behavioral validators
    -> result.json
```

The harness does not generate tasks, repair code, or decide gold answers. A
passing source may later become a gold answer during dataset assembly.

## 2. Decision Invariant

The top-level decision is one of:

- `pass`: compilation, verifier load, and every declared validator passed.
- `fail`: the candidate was validly tested and failed compilation, verifier
  load, output compliance, or at least one behavioral assertion.
- `error`: the harness could not validly complete the requested evaluation.
- `skipped`: an identical complete validation fingerprint already has a final
  result and `--only-new` was requested.

`pass` is forbidden when:

- a validator type is unknown or unimplemented;
- a fixture, map, route, interface, namespace, or expected value is missing;
- the candidate or contract times out;
- the packet oracle cannot parse the input or output;
- a required map cannot be located, reset, initialized, or read;
- a live packet cannot be observed reliably;
- cleanup fails or leaves a program, map, link, namespace, or interface behind;
- a tool returns output that the harness cannot parse.

## 3. Supported Evaluation Matrix

The learning mode is metadata and does not affect candidate execution.
Synthesis and repair outputs use the same validation pipeline.

| Application category | Required validator capabilities |
|---|---|
| Packet Filtering & Security | `packet_action`; optionally maps |
| Packet Inspection & Telemetry | `packet_action` plus `map_state` |
| Protocol Transformation | `packet_action` plus `packet_bytes` |
| Network Routing & Forwarding | `packet_action` for decision-only tasks; `live_forward` for actual forwarding |

Difficulty is task metadata. It must not change pass criteria.

## 4. Repository Layout

```text
verifier/
├── __init__.py
├── cli.py
├── contracts.py
├── compiler.py
├── loader.py
├── runner.py
├── packet_oracle.py
├── maps.py
├── topology.py
├── cache.py
├── results.py
└── environment.py

data/
├── inbox/
│   ├── tasks/<task_id>/task.json
│   ├── tests/<task_id>/tests.json
│   └── candidates/<task_id>/<candidate_id>/
│       ├── program.c
│       └── manifest.json
└── validation/
    ├── raw/<candidate_id>-<fingerprint>.json
    └── cache.sqlite3
```

Runtime files must live outside the repository in a per-run directory created
with `tempfile.TemporaryDirectory`, except bpffs pins under the exact prefix:

```text
/sys/fs/bpf/bpf_guardian/<run_id>/
```

## 5. Input Contracts

Validate all inputs against the bundled JSON Schemas before compiling.
Additionally enforce:

- IDs match `^[a-z0-9][a-z0-9_-]{2,127}$`.
- All referenced paths resolve beneath the repository root.
- Symlinks are rejected for candidate source and packet fixtures.
- Candidate source is UTF-8, regular, non-empty, and at most 256 KiB.
- `task_id` is identical across task, tests, and manifest.
- `candidate_id` and source SHA-256 match the manifest.
- A task contains at least one validator and each validator at least one case.
- Case IDs are unique within the task.
- Expected output is explicit; absence is not interpreted as success.

## 6. CLI Contract

Required single-candidate command:

```bash
python -m verifier.cli validate \
  --task data/inbox/tasks/<task_id>/task.json \
  --tests data/inbox/tests/<task_id>/tests.json \
  --candidate data/inbox/candidates/<task_id>/<candidate_id>/program.c \
  --manifest data/inbox/candidates/<task_id>/<candidate_id>/manifest.json \
  --result data/validation/raw/<candidate_id>-<fingerprint>.json \
  [--cache data/validation/cache.sqlite3] \
  [--only-new]
```

Required batch command:

```bash
python -m verifier.cli validate-batch \
  --assignment data/assignments/<batch_id>.yaml \
  --only-new
```

The CLI must exit:

- `0` when the operation completed and the decision is `pass` or `skipped`;
- `1` when the candidate decision is `fail`;
- `2` for contract, infrastructure, unsupported, or cleanup `error`.

The result file must be written atomically even when the decision is `fail` or
`error`. Human-readable progress goes to stderr. Machine-readable JSON may go
to stdout only when explicitly requested.

## 7. Validation Fingerprint

Hash the canonical concatenation of:

- candidate source bytes;
- canonical task JSON;
- canonical tests JSON;
- canonical manifest fields excluding timestamps and claimed status;
- bytes of every referenced fixture;
- harness Git commit;
- compiler absolute path and version;
- bpftool absolute path and version;
- kernel release and architecture;
- BTF availability and digest when used;
- effective compile flags;
- validator implementation version;
- live topology specification when applicable.

Only an exact matching final result may be skipped. A changed test, kernel,
compiler, harness, source, map initialization, or topology requires rerun.

## 8. Stage A: Output and Policy Checks

Reject with candidate `fail` when:

- the source contains Markdown fences or surrounding prose;
- no `SEC("xdp")` section is present;
- no license section is present;
- the task requires a single program but multiple XDP entry points exist;
- an ELF-producing source includes out-of-scope program section types;
- source size or declared helper policy is violated.

Do not attempt to infer semantic correctness here.

## 9. Stage B: Compilation

Invoke Clang with a fixed argument list similar to:

```text
clang -O2 -g -Wall -Werror -target bpf
      -D__TARGET_ARCH_x86
      -I/usr/include/<multiarch>
      -c <candidate.c> -o <temporary/program.o>
```

Requirements:

- No `shell=True`, shell interpolation, environment-provided flags, Makefile,
  build script, or candidate-provided include path.
- Minimal allowlisted environment and a fixed working directory.
- CPU, address-space, file-size, process-count, and wall-clock limits.
- Capture stdout, stderr, argv, exit status, duration, compiler version, and
  object SHA-256.
- Verify the object is an ELF BPF relocatable object with expected XDP section.
- Compilation non-zero is candidate `fail`, not harness `error`.
- Tool missing, killed runner, unparseable output, or timeout is `error`.

## 10. Stage C: Kernel Verifier Load

Load the temporary object through libbpf or fixed `bpftool` arguments. Pin only
under the run-specific bpffs prefix. Pin declared maps beneath `maps/`.

Requirements:

- Force program type XDP; never infer and attach another generated section.
- Capture full verifier output using debug logging.
- Record program ID, tag, translated instruction count, map IDs, load duration,
  kernel release, and verifier diagnostic.
- Kernel rejection is candidate `fail` with stage `verifier`.
- Permission, bpffs, tool, resource, or cleanup failure is `error`.
- Loading does not attach the program to any interface.

## 11. Stage D1: `packet_action`

For each case:

1. Read the immutable packet fixture.
2. Optionally construct an allowlisted `xdp_md` context from explicit fields.
3. Execute the pinned program with `BPF_PROG_RUN`/`bpftool prog run`.
4. Parse the returned action exactly.
5. Compare with the declared `XDP_ABORTED`, `XDP_DROP`, `XDP_PASS`, `XDP_TX`,
   or `XDP_REDIRECT` expectation.
6. Save actual action, duration, input hash, and output hash.

An action assertion mismatch is candidate `fail`. The test-run facility does
not prove that `XDP_REDIRECT` actually delivered a packet; such tasks require
`live_forward`.

## 12. Stage D2: `packet_bytes`

Run the packet and request `data_out`. Parse input and output with a trusted
packet oracle independent of candidate code.

Supported assertions must include:

- exact output bytes and output length;
- Ethernet source, destination, and EtherType;
- VLAN presence, ID, priority, and inner EtherType;
- IPv4 version, IHL, total length, source, destination, TTL, protocol, and
  header-checksum validity;
- TCP/UDP ports and checksum validity when requested;
- unchanged payload or explicit byte ranges;
- exact packet-length delta for head/tail transformations.

Unknown protocol layers or assertions are `error`. A parseable mismatch or
invalid requested checksum is candidate `fail`.

## 13. Stage D3: `map_state`

For each case:

1. Identify maps by exact declared name and verify type/key/value sizes.
2. Reset or initialize entries from allowlisted typed values.
3. Execute the declared packet sequence.
4. Read the map through a file descriptor or pinned path.
5. Canonicalize per-CPU values by preserving individual CPU values and, when
   requested, calculating their sum.
6. Compare keys, values, update counts, and absence assertions.

Do not accept a missing map, ambiguous name, unexpected type, stale value, or
failed reset. Those are `error`, not pass.

## 14. Stage D4: `live_forward`

This validator is required only when the task claims real forwarding,
redirection, transmission, FIB behavior, or egress selection.

The harness must:

1. Hold a global privileged-validation lock.
2. Create a uniquely named disposable network namespace.
3. Create only veth devices inside or connected to that namespace.
4. Assign deterministic addresses, routes, neighbour entries, and MTUs from
   the test contract.
5. Initialize only declared configuration, DEVMap, CPUMap, or route state.
6. Attach the candidate only to the disposable ingress veth.
7. Capture on all declared possible egress paths before packet injection.
8. Inject one uniquely identifiable packet.
9. Assert expected egress, non-egress absence, output bytes, and count.
10. Detach, close descriptors, delete pins, and delete the namespace in a
    `finally` path.
11. Verify that no object carrying the run ID remains.

Never use the VPS public interface or default namespace routing state. An
unavailable driver feature or unobservable packet is `error`, not pass.

## 15. Result Contract

Every result includes:

- schema and harness versions;
- task, candidate, parent, learning-mode, application-category, task-family,
  difficulty, and operational failure-stage metadata;
- complete fingerprint and environment fingerprint;
- decision and first failed stage;
- per-stage status, timing, tool invocation metadata, and diagnostics;
- per-case expected and actual assertions;
- hashes of source, object, fixtures, and output packets;
- cleanup status and remaining-object audit;
- timestamps in UTC.

`failure_stage` is operational metadata only. Dataset assembly must not inject
it into model-visible repair prompts.

## 16. Safety Model

- Prefer an unprivileged orchestrator plus a narrowly scoped privileged helper
  for load/test/topology operations.
- Until that split exists, run one root-owned worker serially with a fixed job
  directory and no network-facing API.
- Never run generated userspace executables, scripts, Makefiles, commands,
  containers, or arbitrary loaders.
- Reject includes outside the configured system include roots and candidate
  directory.
- Apply timeouts to compilation, load, each packet run, capture, and cleanup.
- Keep a denylist of public/default-route interfaces and assert that live
  topology names are harness-created.
- Limit program/map counts and memory. Do not leave long-lived pins.
- Store diagnostics verbatim but redact secrets and unrelated host paths.

## 17. Acceptance Gates

The implementation is complete only when `acceptance/run_all.sh --full` proves:

1. A correct filter passes.
2. A syntactically invalid source fails at compilation.
3. An unsafe packet access compiles but fails verifier load.
4. A compiling/loading program with wrong behavior fails packet assertions.
5. A correct packet transformation passes output-byte assertions.
6. An incorrect transformation fails output-byte assertions.
7. A correct telemetry program passes map-state assertions.
8. Stale map state cannot leak across cases.
9. A correct disposable-topology forwarding program passes live egress checks.
10. A wrong egress or missing capture fails.
11. Unsupported validators and missing fixtures return `error`.
12. Identical fingerprints skip only with `--only-new`.
13. Source, test, harness, compiler, and kernel changes invalidate cache.
14. Concurrent privileged attempts serialize safely.
15. No pins, programs, maps, links, namespaces, interfaces, packet captures, or
    temporary files remain after pass, fail, timeout, or interruption.

## 18. Operational Commands

```bash
# Environment check
scripts/vps_preflight.sh

# Fast acceptance: no live forwarding
acceptance/run_all.sh --quick

# Required release acceptance
sudo acceptance/run_all.sh --full

# Candidate batch after agents push
python -m verifier.cli validate-batch \
  --assignment data/assignments/antigravity-001.yaml \
  --only-new
```

The batch summary may list passes and failures, but each candidate must retain
its own immutable result JSON.

## 19. Definition of Done

- All full acceptance cases pass without skipped required capabilities.
- Unit tests cover schemas, path containment, result decisions, action parsing,
  packet parsing/checksums, per-CPU map normalization, cache invalidation, and
  cleanup after injected failures.
- The environment fingerprint is committed with the first result batch.
- The implementation and dependency lock are committed.
- A second clean run produces identical decisions and skips only exact cached
  fingerprints.

## 20. Primary References

- Linux BPF verifier:
  https://docs.kernel.org/bpf/verifier.html
- Running BPF/XDP programs from userspace:
  https://docs.kernel.org/bpf/bpf_prog_run.html
- Current bpftool program command contract:
  https://github.com/torvalds/linux/blob/master/tools/bpf/bpftool/Documentation/bpftool-prog.rst
- XDP redirect implementation and error tracepoints:
  https://docs.kernel.org/bpf/redirect.html
- CPUMap behavior:
  https://docs.kernel.org/bpf/map_cpumap.html
