#!/usr/bin/env bash
set -euo pipefail

project_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$project_root"

batch_id="${1:-batch-001}"
python3 scripts/validate_candidates.py --batch-id "$batch_id"
