#!/usr/bin/env bash
set -euo pipefail

mode="${1:---quick}"
if [[ "$mode" != "--quick" && "$mode" != "--full" ]]; then
    echo "Usage: $0 [--quick|--full]" >&2
    exit 2
fi

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root_dir"

if [[ "$mode" == "--full" && "${EUID}" -ne 0 ]]; then
    echo "ERROR: --full requires root for disposable namespace tests" >&2
    exit 2
fi

scripts/vps_preflight.sh

python3 -m json.tool schemas/task.schema.json >/dev/null
python3 -m json.tool schemas/tests.schema.json >/dev/null
python3 -m json.tool schemas/manifest.schema.json >/dev/null
python3 -m json.tool schemas/result.schema.json >/dev/null

generated_dir="$root_dir/acceptance/generated"
mkdir -p "$generated_dir"
python3 acceptance/generate_packets.py "$generated_dir"

temporary_dir="$(mktemp -d /tmp/bpfg-acceptance.XXXXXX)"
cleanup_temporary() {
    rm -rf -- "$temporary_dir"
}
trap cleanup_temporary EXIT

cache_path="$temporary_dir/cache.sqlite3"

run_case() {
    local case_name="$1"
    local task_path="$2"
    local tests_path="$3"
    local source_path="$4"
    local task_id="$5"
    local expected_decision="$6"
    local expected_stage="${7:-}"
    local only_new="${8:-false}"
    local manifest_path="$temporary_dir/${case_name}.manifest.json"
    local result_path="$temporary_dir/${case_name}.result.json"
    local candidate_id="${9:-accept_${case_name//-/_}}"

    python3 acceptance/make_manifest.py \
        --candidate-id "$candidate_id" \
        --task-id "$task_id" \
        --source "$source_path" \
        --output "$manifest_path"

    command=(
        python3 -m verifier.cli validate
        --task "$task_path"
        --tests "$tests_path"
        --candidate "$source_path"
        --manifest "$manifest_path"
        --result "$result_path"
        --cache "$cache_path"
    )
    if [[ "$only_new" == "true" ]]; then
        command+=(--only-new)
    fi

    set +e
    "${command[@]}"
    actual_exit=$?
    set -e

    case "$expected_decision" in
        pass|skipped) expected_exit=0 ;;
        fail) expected_exit=1 ;;
        error) expected_exit=2 ;;
    esac

    if [[ "$actual_exit" -ne "$expected_exit" ]]; then
        echo "ERROR: $case_name expected exit $expected_exit, got $actual_exit" >&2
        exit 1
    fi

    if [[ -n "$expected_stage" ]]; then
        python3 acceptance/assert_result.py \
            "$result_path" "$expected_decision" "$expected_stage"
    else
        python3 acceptance/assert_result.py "$result_path" "$expected_decision"
    fi
}

filter_task="acceptance/contracts/filter_task.json"
filter_tests="acceptance/contracts/filter_tests.json"

run_case \
    filter-good "$filter_task" "$filter_tests" \
    acceptance/fixtures/filter_good.c accept_filter_tcp23 pass

run_case \
    compile-fail "$filter_task" "$filter_tests" \
    acceptance/fixtures/compile_fail.c accept_filter_tcp23 fail compiler

run_case \
    verifier-fail "$filter_task" "$filter_tests" \
    acceptance/fixtures/verifier_fail.c accept_filter_tcp23 fail verifier

run_case \
    behavior-fail "$filter_task" "$filter_tests" \
    acceptance/fixtures/filter_wrong.c accept_filter_tcp23 fail behavior

run_case \
    transform-good acceptance/contracts/transform_task.json \
    acceptance/contracts/transform_tests.json \
    acceptance/fixtures/transform_swap_mac.c accept_transform_mac pass

run_case \
    transform-fail acceptance/contracts/transform_task.json \
    acceptance/contracts/transform_tests.json \
    acceptance/fixtures/transform_noop.c accept_transform_mac fail behavior

run_case \
    telemetry-good acceptance/contracts/telemetry_task.json \
    acceptance/contracts/telemetry_tests.json \
    acceptance/fixtures/telemetry_counter.c accept_telemetry_protocol pass

run_case \
    missing-fixture "$filter_task" acceptance/contracts/missing_fixture_tests.json \
    acceptance/fixtures/filter_good.c accept_filter_tcp23 error infrastructure

run_case \
    unsupported-validator "$filter_task" acceptance/contracts/unsupported_tests.json \
    acceptance/fixtures/filter_good.c accept_filter_tcp23 error policy

run_case \
    filter-good-cache "$filter_task" "$filter_tests" \
    acceptance/fixtures/filter_good.c accept_filter_tcp23 skipped "" true \
    accept_filter_good

if [[ "$mode" == "--full" ]]; then
    run_case \
        live-forward acceptance/contracts/forward_task.json \
        acceptance/contracts/forward_tests.json \
        acceptance/fixtures/forward_config.c accept_live_forward pass
fi

if [[ -d /sys/fs/bpf/bpf_guardian ]] && \
   find /sys/fs/bpf/bpf_guardian -mindepth 1 -print -quit | grep -q .; then
    echo "ERROR: acceptance run left objects under /sys/fs/bpf/bpf_guardian" >&2
    find /sys/fs/bpf/bpf_guardian -mindepth 1 -maxdepth 3 -print >&2
    exit 1
fi

if ip netns list | awk '{print $1}' | grep -Eq '^bpfg_(accept|run|test)'; then
    echo "ERROR: acceptance run left a BPF-Guardian network namespace" >&2
    ip netns list >&2
    exit 1
fi

echo "All $mode BPF-Guardian harness acceptance cases passed"
