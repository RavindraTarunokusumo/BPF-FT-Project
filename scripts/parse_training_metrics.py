#!/usr/bin/env python3
import json
from pathlib import Path

metrics_file = Path("runs/tinker/nemotron-bpf-rl-n3/pilot/metrics.jsonl")
lines = [json.loads(l) for l in metrics_file.read_text(encoding="utf-8").strip().splitlines()]

print(f"{'Step':>4} | {'R_tot':>6} | {'Pass@1':>6} | {'Solve@2':>7} | {'Rec':>5} | {'T2_Att':>6} | {'Rec_C':>6} | {'Rec_V':>6} | {'Rec_B':>6} | {'KL_base':>7} | {'Mixed':>5}")
print("-" * 80)
for m in lines:
    s = m['step']
    r = m['env/all/reward/total']
    p1 = m['env/all/pass/pass_at_1']
    s2 = m['env/all/pass/solve_at_2']
    rec = m['env/all/pass/recovered']
    t2_att = m['env/all/turn_2/attempted']
    r_c = m.get('env/all/recovery/from_compile_failure', 0.0)
    r_v = m.get('env/all/recovery/from_verifier_failure', 0.0)
    r_b = m.get('env/all/recovery/from_behavioral_failure', 0.0)
    kl = m.get('kl_policy_base', 0.0)
    mix = m['env/all/by_group/frac_mixed']
    print(f"{s:4d} | {r:6.3f} | {p1:6.3f} | {s2:7.3f} | {rec:5.3f} | {t2_att:6.3f} | {r_c:6.3f} | {r_v:6.3f} | {r_b:6.3f} | {kl:7.4f} | {mix:5.2f}")
