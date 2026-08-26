# VPS Agent Assignment: Build the BPF-Guardian Validation Harness

Work in the BPF-Guardian repository on the VPS. Read
`VPS_HARNESS_SPEC.md` completely before changing files.

Implement the harness described there under `verifier/`, install its pinned
Python dependencies, and expose this command:

```bash
python -m verifier.cli validate \
  --task <task.json> \
  --tests <tests.json> \
  --candidate <program.c> \
  --manifest <manifest.json> \
  --result <result.json>
```

Non-negotiable rules:

1. A candidate may be marked `pass` only if it compiles, loads through the
   kernel verifier, and every validator declared in `tests.json` executes and
   passes.
2. Missing fixtures, unsupported validators, unavailable topology, malformed
   contracts, timeouts, infrastructure failures, or cleanup failures must
   produce `error`, never `pass`.
3. Never execute generated shell commands. Treat `program.c` as untrusted
   bytes and invoke tools through fixed argument arrays without `shell=True`.
4. Never attach generated XDP programs to the VPS public interface. Live tests
   may use only disposable network namespaces and veth devices created by the
   harness.
5. Do not overwrite candidate source, task specifications, tests, or previous
   result records.
6. Preserve exact compiler and verifier diagnostics in the result record.
7. Cache only by the complete validation fingerprint defined in the spec.
8. Run privileged validation serially until isolation and cleanup tests pass.

Required workflow:

1. Run `scripts/vps_preflight.sh`.
2. Implement the schemas and CLI contract exactly.
3. Implement validators in this order:
   `packet_action`, `packet_bytes`, `map_state`, `live_forward`.
4. Run `acceptance/run_all.sh --quick` after each validator milestone.
5. Run `sudo acceptance/run_all.sh --full` before declaring completion.
6. Run the repository unit tests and static checks.
7. Commit the implementation and report the commit, environment fingerprint,
   acceptance results, and any unsupported kernel feature.

Do not relax an acceptance assertion to make the suite green. Fix the harness
or report a concrete kernel/tooling blocker.
