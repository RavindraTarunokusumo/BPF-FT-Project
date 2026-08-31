"""
Script to build full defs_protocol_transformation.py and defs_network_routing_forwarding.py.
"""

import sys
import os

sys.path.insert(0, os.path.abspath("."))

def main():
    base_dir = os.path.dirname(os.path.abspath(__file__))
    
    # 1. Generate PTR
    ptr_code = generate_ptr_code()
    with open(os.path.join(base_dir, "defs_protocol_transformation.py"), "w", encoding="utf-8") as f:
        f.write(ptr_code)
    print("Generated defs_protocol_transformation.py")
    
    # 2. Generate NRF
    nrf_code = generate_nrf_code()
    with open(os.path.join(base_dir, "defs_network_routing_forwarding.py"), "w", encoding="utf-8") as f:
        f.write(nrf_code)
    print("Generated defs_network_routing_forwarding.py")

def generate_ptr_code() -> str:
    # Full 30 PTR tasks
    from scripts.synthesis_benchmark_gen.generator_ptr_data import get_all_ptr_tasks_code
    return get_all_ptr_tasks_code()

def generate_nrf_code() -> str:
    # Full 30 NRF tasks
    from scripts.synthesis_benchmark_gen.generator_nrf_data import get_all_nrf_tasks_code
    return get_all_nrf_tasks_code()

if __name__ == "__main__":
    main()
