#!/usr/bin/env bash
# BPF-Guardian Tinker SFT Production Runner
set -euo pipefail

: "${TINKER_API_KEY:?Error: TINKER_API_KEY must be set in environment before starting SFT}"

command -v uv >/dev/null 2>&1 || {
    echo "Error: uv is required to run this script. Install uv: https://docs.astral.sh/uv/" >&2
    exit 1
}

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_ROOT"

echo "======================================================================"
echo "BPF-Guardian: Running Tinker SFT Controller"
echo "======================================================================"

exec uv run python training/train_tinker_sft.py \
    --train-file data/sft/frozen/v1/train.jsonl \
    --validation-file data/sft/frozen/v1/validation.jsonl \
    --manifest-file data/sft/frozen/v1/freeze_manifest.json \
    --log-root runs/tinker \
    "$@"
