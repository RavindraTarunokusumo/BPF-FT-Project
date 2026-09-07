import os
from pathlib import Path
from huggingface_hub import HfApi

env_file = Path('.env')
for line in env_file.read_text(encoding='utf-8').splitlines():
    line = line.strip()
    if line and not line.startswith('#') and '=' in line:
        k, v = line.split('=', 1)
        os.environ[k.strip()] = v.strip().strip('"\'')

api = HfApi()

print("=" * 70)
print("Uploading BPF-Guardian Datasets to Hugging Face Hub")
print("=" * 70)

# 1. Upload bpf-guardian-sft
sft_dir = Path("build/datasets/bpf-guardian-sft")
print(f"\n[+] Uploading {sft_dir} to rvindra/bpf-guardian-sft...")
api.upload_folder(
    folder_path=str(sft_dir),
    repo_id="rvindra/bpf-guardian-sft",
    repo_type="dataset",
    commit_message="Initial release: Combined eBPF/XDP SFT instruction-tuning corpus (2,320 examples)",
)
print("[+] Successfully uploaded rvindra/bpf-guardian-sft!")

# 2. Upload bpf-guardian-rl
rl_dir = Path("build/datasets/bpf-guardian-rl")
print(f"\n[+] Uploading {rl_dir} to rvindra/bpf-guardian-rl...")
api.upload_folder(
    folder_path=str(rl_dir),
    repo_id="rvindra/bpf-guardian-rl",
    repo_type="dataset",
    commit_message="Initial release: Certified eBPF/XDP RLVR benchmark (264 stratified tasks)",
)
print("[+] Successfully uploaded rvindra/bpf-guardian-rl!")
