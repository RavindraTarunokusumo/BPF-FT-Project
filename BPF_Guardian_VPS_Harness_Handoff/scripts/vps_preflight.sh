#!/usr/bin/env bash
set -euo pipefail

required_commands=(clang bpftool python3 ip mountpoint sha256sum)
missing=0

for command_name in "${required_commands[@]}"; do
    if ! command -v "$command_name" >/dev/null 2>&1; then
        echo "MISSING command: $command_name" >&2
        missing=1
    fi
done

if (( missing != 0 )); then
    exit 1
fi

kernel_release="$(uname -r)"
architecture="$(uname -m)"
clang_version="$(clang --version | head -n 1)"
bpftool_version="$(bpftool version | head -n 1)"

if [[ "$architecture" != "x86_64" ]]; then
    echo "ERROR: this handoff currently specifies __TARGET_ARCH_x86; found $architecture" >&2
    exit 1
fi

if [[ ! -r /sys/kernel/btf/vmlinux ]]; then
    echo "ERROR: /sys/kernel/btf/vmlinux is unavailable" >&2
    exit 1
fi

if ! mountpoint -q /sys/fs/bpf; then
    echo "ERROR: bpffs is not mounted at /sys/fs/bpf" >&2
    exit 1
fi

preflight_namespace="bpfg_preflight_$$"
cleanup_namespace() {
    ip netns delete "$preflight_namespace" >/dev/null 2>&1 || true
}
trap cleanup_namespace EXIT

if ! ip netns add "$preflight_namespace"; then
    echo "ERROR: cannot create a disposable network namespace" >&2
    exit 1
fi
ip netns delete "$preflight_namespace"
trap - EXIT

echo "VPS harness preflight passed"
echo "kernel=$kernel_release"
echo "architecture=$architecture"
echo "clang=$clang_version"
echo "bpftool=$bpftool_version"
echo "btf_sha256=$(sha256sum /sys/kernel/btf/vmlinux | awk '{print $1}')"
