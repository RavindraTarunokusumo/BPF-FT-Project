#!/usr/bin/env bash
# BPF-Guardian VPS Rollout Verification Script
# Executes Clang BPF compilation, bpftool kernel verifier loading, and packet tests on Linux VPS.
set -euo pipefail

export PATH="$HOME/.cargo/bin:$HOME/.local/bin:/root/.cargo/bin:/root/.local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:${PATH:-}"

if [[ $# -lt 1 ]]; then
    echo "Usage: $0 <rollout_directory> [extra import args...]" >&2
    echo "Example: $0 runs/evaluation/qwen3-8b-sft/rollout-001" >&2
    exit 1
fi

ROLLOUT_DIR="$1"
shift 1 || true

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_ROOT"

if [[ ! -d "$ROLLOUT_DIR" ]]; then
    echo "Error: Rollout directory not found: $ROLLOUT_DIR" >&2
    exit 1
fi

CANDIDATES_DIR="$ROLLOUT_DIR/candidates"
VERIFICATION_DIR="$ROLLOUT_DIR/verification"
RAW_DIR="$VERIFICATION_DIR/raw"
BENCHMARK_INDEX="data/calibration/index.jsonl"

# Read benchmark index from manifest if present
if [[ -f "$ROLLOUT_DIR/manifest.json" ]]; then
    RAW_MANIFEST_INDEX=$(grep -o '"benchmark_index": "[^"]*' "$ROLLOUT_DIR/manifest.json" | cut -d'"' -f4 | sed 's/\\\\/\//g' || true)
    if [[ -n "$RAW_MANIFEST_INDEX" && -f "$RAW_MANIFEST_INDEX" ]]; then
        BENCHMARK_INDEX="$RAW_MANIFEST_INDEX"
    elif [[ -f "data/benchmark/repair/index.jsonl" && "$ROLLOUT_DIR" =~ "repair" ]]; then
        BENCHMARK_INDEX="data/benchmark/repair/index.jsonl"
    elif [[ -f "data/benchmark/synthesis/index.jsonl" && "$ROLLOUT_DIR" =~ "synthesis" ]]; then
        BENCHMARK_INDEX="data/benchmark/synthesis/index.jsonl"
    elif [[ "$RAW_MANIFEST_INDEX" =~ (data/.*) && -f "${BASH_REMATCH[1]}" ]]; then
        BENCHMARK_INDEX="${BASH_REMATCH[1]}"
    fi
fi

mkdir -p "$RAW_DIR"

echo "======================================================================"
echo "BPF-Guardian VPS Rollout Verification"
echo "Rollout Directory: $ROLLOUT_DIR"
echo "Benchmark Index:   $BENCHMARK_INDEX"
echo "Candidates Dir:    $CANDIDATES_DIR"
echo "Raw Results Dir:   $RAW_DIR"
echo "======================================================================"

# Check if running on Linux with bpftool and clang
HAS_BPF_TOOLCHAIN=true
command -v clang >/dev/null 2>&1 || HAS_BPF_TOOLCHAIN=false
command -v bpftool >/dev/null 2>&1 || HAS_BPF_TOOLCHAIN=false

if [[ "$HAS_BPF_TOOLCHAIN" == "true" ]]; then
    echo "[+] Linux BPF toolchain (clang, bpftool) detected. Running live kernel validation..."
    
    uv run python -c "
import json
import os
import sys
from pathlib import Path
from verifier.engine import BPFValidator

validator = BPFValidator()
candidates_dir = Path('$CANDIDATES_DIR')
raw_dir = Path('$RAW_DIR')
index_path = Path('$BENCHMARK_INDEX')

task_specs = {}
for line in index_path.read_text(encoding='utf-8').splitlines():
    if line.strip():
        t = json.loads(line)
        task_specs[t['task_id']] = t

c_files = list(candidates_dir.glob('*/*.c'))
print(f'Found {len(c_files)} candidate C programs to verify.')

for idx, c_file in enumerate(c_files, start=1):
    task_id = c_file.parent.name
    cand_id = c_file.stem
    task_spec = task_specs.get(task_id, {'task_id': task_id, 'tests': []})
    
    cat = task_spec.get('application_category', '')
    diff = task_spec.get('difficulty', '')
    
    # Load detailed test specs if available across possible benchmark locations
    for test_candidate in [
        Path(f'data/calibration/{cat}/{diff}/{task_id}/tests.json'),
        Path(f'data/benchmark/synthesis/{cat}/{diff}/{task_id}/tests.json'),
        Path(f'data/benchmark/repair/{cat}/{diff}/{task_id}/tests.json'),
        *Path('data').glob(f'**/{task_id}/tests.json'),
    ]:
        if test_candidate.is_file():
            try:
                task_spec['tests'] = json.loads(test_candidate.read_text(encoding='utf-8')).get('tests', [])
                break
            except Exception:
                pass

    res = validator.validate_candidate(
        task_id=task_id,
        candidate_id=cand_id,
        source_path=c_file,
        task_spec=task_spec,
    )
    
    out_json = raw_dir / f'{task_id}_{cand_id}.json'
    out_json.write_text(json.dumps(res, indent=2), encoding='utf-8')
    if idx % 10 == 0 or idx == len(c_files):
        print(f'  Verified {idx}/{len(c_files)} candidates...')
"
else
    echo "[!] Live BPF toolchain not found on host (non-Linux or unprivileged). Simulating verification..."
fi

# Aggregate results
uv run python training/import_verifier_results.py \
    --rollout-dir "$ROLLOUT_DIR" \
    --output-dir "$VERIFICATION_DIR" \
    --raw-dir "$RAW_DIR" \
    --benchmark-index "$BENCHMARK_INDEX" \
    "$@"
