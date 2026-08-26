# BPF-Guardian VPS Harness Handoff

This bundle is intended to be copied into the root of the BPF-Guardian
repository and assigned to the VPS coding agent.

## Contents

- `AGENT_PROMPT.md`: copy-paste assignment for the VPS agent.
- `VPS_HARNESS_SPEC.md`: normative implementation contract.
- `schemas/`: input and result JSON contracts.
- `scripts/vps_preflight.sh`: VPS capability check.
- `acceptance/`: executable black-box acceptance suite and known candidates.

## Installation into the repository

Copy the contents of this bundle into the repository root without overwriting
unrelated user changes. Commit the handoff before the agent implements the
harness so specification changes remain auditable.

## Required commands

```bash
chmod +x scripts/vps_preflight.sh acceptance/run_all.sh
scripts/vps_preflight.sh
```

After the agent implements `verifier/`:

```bash
acceptance/run_all.sh --quick
sudo acceptance/run_all.sh --full
```

The quick suite covers compile, verifier, action, packet-byte, map-state,
unsupported-contract, missing-fixture, incremental-cache, and cleanup behavior.
The full suite additionally requires actual forwarding through a disposable
network namespace and veth topology.

## Trust rule

The result `pass` means every validator declared by that task executed and
passed. Anything unavailable, missing, unsupported, timed out, or unobservable
must be `error`; it must never be silently skipped or treated as success.
