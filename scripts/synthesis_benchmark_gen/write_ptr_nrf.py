"""
Generator for defs_protocol_transformation.py and defs_network_routing_forwarding.py
Writes out all 30 tasks for PTR and all 30 tasks for NRF.
"""

import os
import sys

def write_files():
    base_dir = os.path.dirname(os.path.abspath(__file__))
    
    # Write PTR
    ptr_path = os.path.join(base_dir, "defs_protocol_transformation.py")
    print(f"Writing {ptr_path}...")
    with open(ptr_path, "w", encoding="utf-8") as f:
        f.write(generate_ptr_source())
        
    # Write NRF
    nrf_path = os.path.join(base_dir, "defs_network_routing_forwarding.py")
    print(f"Writing {nrf_path}...")
    with open(nrf_path, "w", encoding="utf-8") as f:
        f.write(generate_nrf_source())
        
    print("Files written successfully.")

def generate_ptr_source() -> str:
    # Build complete python source for PTR
    from scripts.synthesis_benchmark_gen.defs_ptr_full import get_ptr_source_code
    return get_ptr_source_code()

def generate_nrf_source() -> str:
    # Build complete python source for NRF
    from scripts.synthesis_benchmark_gen.defs_nrf_full import get_nrf_source_code
    return get_nrf_source_code()

if __name__ == "__main__":
    write_files()
