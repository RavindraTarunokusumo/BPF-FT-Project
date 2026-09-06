import json
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from training.run_phase_n1_evaluations import load_qwen_baseline_results, load_task_results, SUITES

base_results = load_qwen_baseline_results()
qwen_tasks = base_results['qwen_sft_v2']

eval_dir = Path('runs/evaluation/nemotron-sft-v1-full')
nemo_tasks = {}
for s in ['calibration-36', 'synthesis-120', 'repair-120', 'rl-v2-dev-48', 'rl-v2-confirmation-60']:
    nemo_tasks.update(load_task_results(eval_dir / s))

cat_stats = {}
diff_stats = {}
suite_stats = {}

for s in ['calibration-36', 'synthesis-120', 'repair-120', 'rl-v2-dev-48', 'rl-v2-confirmation-60']:
    idx_file = SUITES[s]['index']
    with open(idx_file, 'r', encoding='utf-8') as f:
        for line in f:
            if not line.strip():
                continue
            t = json.loads(line)
            tid = t['task_id']
            cat = t.get('application_category', 'unknown')
            diff = t.get('difficulty', 'unknown')

            for group, key in [(cat_stats, cat), (diff_stats, diff), (suite_stats, s)]:
                if key not in group:
                    group[key] = {'total': 0, 'qwen_pass': 0, 'nemo_pass': 0, 'regressions': 0, 'recoveries': 0}
                q_pass = qwen_tasks.get(tid, False)
                n_pass = nemo_tasks.get(tid, False)
                group[key]['total'] += 1
                if q_pass:
                    group[key]['qwen_pass'] += 1
                if n_pass:
                    group[key]['nemo_pass'] += 1
                if q_pass and not n_pass:
                    group[key]['regressions'] += 1
                if not q_pass and n_pass:
                    group[key]['recoveries'] += 1

print("\n--- SUITE BREAKDOWN ---")
for k, v in suite_stats.items():
    net = v['nemo_pass'] - v['qwen_pass']
    print(f"{k:<25}: Total={v['total']:<3} | Qwen={v['qwen_pass']:<3} | Nemo={v['nemo_pass']:<3} | Net={net:+3} | Regressions={v['regressions']:<2} | Recoveries={v['recoveries']:<2}")

print("\n--- CATEGORY BREAKDOWN ---")
for k, v in cat_stats.items():
    net = v['nemo_pass'] - v['qwen_pass']
    print(f"{k:<30}: Total={v['total']:<3} | Qwen={v['qwen_pass']:<3} | Nemo={v['nemo_pass']:<3} | Net={net:+3} | Regressions={v['regressions']:<2} | Recoveries={v['recoveries']:<2}")

print("\n--- DIFFICULTY BREAKDOWN ---")
for k, v in diff_stats.items():
    net = v['nemo_pass'] - v['qwen_pass']
    print(f"{k:<15}: Total={v['total']:<3} | Qwen={v['qwen_pass']:<3} | Nemo={v['nemo_pass']:<3} | Net={net:+3} | Regressions={v['regressions']:<2} | Recoveries={v['recoveries']:<2}")
