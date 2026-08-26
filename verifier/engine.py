#!/usr/bin/env python3
"""
BPF-Guardian Verification Engine
Validates XDP/eBPF candidates through:
1. Compilation using Clang BPF target
2. Kernel verifier loading via bpftool
3. Behavioral packet testing via BPF_PROG_TEST_RUN (bpftool prog run)
"""

from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

ACTION_NAME_TO_INT = {
    "XDP_ABORTED": 0,
    "XDP_DROP": 1,
    "XDP_PASS": 2,
    "XDP_TX": 3,
    "XDP_REDIRECT": 4,
}

ACTION_INT_TO_NAME = {v: k for k, v in ACTION_NAME_TO_INT.items()}


def compute_sha256(file_path: Path) -> str:
    digest = hashlib.sha256()
    digest.update(file_path.read_bytes())
    return digest.hexdigest()


class BPFValidator:
    def __init__(
        self,
        clang_path: str = "clang",
        bpftool_path: str = "bpftool",
        include_paths: Optional[List[str]] = None,
    ):
        self.clang_path = clang_path
        self.bpftool_path = bpftool_path
        self.include_paths = include_paths or [
            "/usr/include/x86_64-linux-gnu",
            "/usr/include",
        ]

    def compile_candidate(
        self, source_path: Path, output_obj: Path
    ) -> Tuple[bool, str, str, int]:
        """Compiles C source file to BPF ELF object."""
        cmd = [
            self.clang_path,
            "-O2",
            "-g",
            "-Wall",
            "-Wextra",
            "-target",
            "bpf",
        ]
        for inc in self.include_paths:
            cmd.extend(["-I", inc])
        cmd.extend(["-c", str(source_path), "-o", str(output_obj)])

        try:
            res = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30,
            )
            return (
                res.returncode == 0,
                res.stdout,
                res.stderr,
                res.returncode,
            )
        except subprocess.TimeoutExpired:
            return False, "", "Compilation timed out after 30s", -1
        except Exception as e:
            return False, "", f"Compilation execution error: {e}", -1

    def load_candidate(
        self, obj_path: Path, pin_path: Path
    ) -> Tuple[bool, str, str, str]:
        """Loads BPF object into kernel verifier and pins it."""
        if pin_path.exists():
            try:
                pin_path.unlink()
            except Exception:
                pass

        # Use bpftool prog load with debug logging for rich verifier output on failure
        cmd = [self.bpftool_path, "-d", "prog", "load", str(obj_path), str(pin_path)]
        try:
            res = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30,
            )
            passed = res.returncode == 0 and pin_path.exists()
            return (
                passed,
                res.stdout,
                res.stderr,
                res.stderr if not passed else "",
            )
        except subprocess.TimeoutExpired:
            return False, "", "Verifier loading timed out after 30s", "Timeout"
        except Exception as e:
            return False, "", f"Verifier execution error: {e}", str(e)

    def run_test_packet(
        self, pin_path: Path, packet_bytes: bytes, temp_dir: Path
    ) -> Tuple[bool, Optional[int], str, str]:
        """Runs a single packet through the pinned BPF program."""
        pkt_in = temp_dir / "pkt_in.bin"
        pkt_out = temp_dir / "pkt_out.bin"
        pkt_in.write_bytes(packet_bytes)
        if pkt_out.exists():
            pkt_out.unlink()

        cmd = [
            self.bpftool_path,
            "prog",
            "run",
            "pinned",
            str(pin_path),
            "data_in",
            str(pkt_in),
            "data_out",
            str(pkt_out),
        ]
        try:
            res = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=10,
            )
            if res.returncode != 0:
                return False, None, res.stdout, res.stderr

            # Parse return value from stdout e.g. "Return value: 2, duration: 899ns"
            match = re.search(r"Return value:\s*(\d+)", res.stdout)
            if match:
                ret_val = int(match.group(1))
                return True, ret_val, res.stdout, res.stderr
            else:
                return False, None, res.stdout, f"Could not parse return value from: {res.stdout}"
        except subprocess.TimeoutExpired:
            return False, None, "", "Packet test timed out after 10s"
        except Exception as e:
            return False, None, "", f"Packet test execution error: {e}"

    def validate_candidate(
        self,
        batch_id: str,
        task_id: str,
        candidate_id: str,
        source_path: Path,
        task_spec: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Performs full validation (compile, verifier load, behavioral test) on a candidate."""
        source_sha256 = compute_sha256(source_path)
        timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()

        result: Dict[str, Any] = {
            "batch_id": batch_id,
            "task_id": task_id,
            "candidate_id": candidate_id,
            "source_path": str(source_path).replace("\\", "/"),
            "source_sha256": source_sha256,
            "timestamp": timestamp,
            "compile": {
                "pass": False,
                "stdout": "",
                "stderr": "",
                "returncode": -1,
            },
            "verifier": {
                "pass": False,
                "stdout": "",
                "stderr": "",
                "log": "",
            },
            "behavioral": {
                "pass": False,
                "passed_tests": 0,
                "total_tests": 0,
                "details": [],
            },
            "passed": False,
            "diagnostic": None,
        }

        with tempfile.TemporaryDirectory(prefix="bpf_val_") as temp_dir_str:
            temp_dir = Path(temp_dir_str)
            obj_path = temp_dir / "candidate.o"
            pin_path = Path(f"/sys/fs/bpf/bpf_guard_{task_id}_{candidate_id}_{os.getpid()}")

            # 1. Compile
            c_pass, c_out, c_err, c_code = self.compile_candidate(source_path, obj_path)
            result["compile"] = {
                "pass": c_pass,
                "stdout": c_out,
                "stderr": c_err,
                "returncode": c_code,
            }

            if not c_pass:
                result["passed"] = False
                result["diagnostic"] = f"Compilation failed:\n{c_err.strip()}"
                return result

            # 2. Verifier Load
            v_pass, v_out, v_err, v_log = self.load_candidate(obj_path, pin_path)
            result["verifier"] = {
                "pass": v_pass,
                "stdout": v_out,
                "stderr": v_err,
                "log": v_log,
            }

            if not v_pass:
                result["passed"] = False
                result["diagnostic"] = f"Kernel verifier rejected program:\n{v_err.strip() or v_out.strip()}"
                # Clean up if pinned
                if pin_path.exists():
                    try:
                        pin_path.unlink()
                    except Exception:
                        pass
                return result

            # 3. Behavioral Tests
            test_cases = task_spec.get("tests", [])
            total_tests = len(test_cases)
            passed_tests = 0
            details: List[Dict[str, Any]] = []
            behavioral_failures: List[str] = []

            try:
                for test_case in test_cases:
                    t_name = test_case.get("name", "unnamed_test")
                    t_desc = test_case.get("description", "")
                    pkt_hex = test_case.get("packet_hex", "")
                    expected_action = test_case.get("expected_action")

                    expected_int = (
                        ACTION_NAME_TO_INT.get(expected_action)
                        if isinstance(expected_action, str)
                        else int(expected_action)
                    )

                    try:
                        pkt_bytes = bytes.fromhex(pkt_hex)
                    except ValueError as e:
                        details.append({
                            "name": t_name,
                            "pass": False,
                            "error": f"Invalid packet hex: {e}",
                        })
                        behavioral_failures.append(f"Test '{t_name}': invalid packet hex")
                        continue

                    run_success, actual_int, run_out, run_err = self.run_test_packet(
                        pin_path, pkt_bytes, temp_dir
                    )

                    actual_action_name = ACTION_INT_TO_NAME.get(
                        actual_int, f"UNKNOWN({actual_int})"
                    ) if actual_int is not None else "ERROR"

                    if run_success and actual_int == expected_int:
                        passed_tests += 1
                        details.append({
                            "name": t_name,
                            "description": t_desc,
                            "pass": True,
                            "expected": expected_action,
                            "actual": actual_action_name,
                        })
                    else:
                        details.append({
                            "name": t_name,
                            "description": t_desc,
                            "pass": False,
                            "expected": expected_action,
                            "actual": actual_action_name,
                            "stderr": run_err,
                        })
                        behavioral_failures.append(
                            f"Test '{t_name}' failed: expected {expected_action} ({expected_int}), got {actual_action_name} ({actual_int})"
                        )

                b_pass = total_tests > 0 and passed_tests == total_tests
                result["behavioral"] = {
                    "pass": b_pass,
                    "passed_tests": passed_tests,
                    "total_tests": total_tests,
                    "details": details,
                }

                if b_pass:
                    result["passed"] = True
                    result["diagnostic"] = None
                else:
                    result["passed"] = False
                    result["diagnostic"] = "Behavioral tests failed:\n" + "\n".join(behavioral_failures)

            finally:
                if pin_path.exists():
                    try:
                        pin_path.unlink()
                    except Exception:
                        pass

        return result
