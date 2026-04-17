# sections.py
"""
Section Analysis Module

Analyzes PE sections (.text, .data, .rdata, etc.) for:
- Entropy (compression/encryption detection) - values > 7.4 suggest packing
- Permissions (read, write, execute flags)
- Size anomalies (very small/large sections)
- Risk scoring based on characteristics

High entropy + executable = likely packed/encrypted code
"""

import pefile
from typing import Any, Callable
from config.sections_config import PACKER_DETECTION_CONFIG

def analyze_sections(pe: pefile.PE, console: Any, calc_entropy_func: Callable) -> tuple:
    """
    Analyze PE sections for packing, permissions, and anomalies.
    
    Args:
        pe: pefile.PE object representing the PE file
        console: Rich Console for formatted output
        calc_entropy_func: Function to calculate section entropy
    
    Returns:
        Tuple[int, List[str]]: (total_risk, output_lines)
            - total_risk: Sum of risk scores from all sections
            - output_lines: List of analysis output lines
    
    Entropy interpretation:
        - < 5.0: Uncompressed (normal code/data)
        - 5.0-7.0: Possibly compressed
        - > 7.4: Likely packed/encrypted malicious code
    
    Risk factors per section:
        - High entropy with X (execute) flag: Packed code
        - Unusual section names: Obfuscation attempt
        - Unaligned sizes: Suspicious padding
    
    Example:
        >>> total_risk, lines = analyze_sections(pe, console, entropy_fn)
        >>> print(f"Total section risk: {total_risk}")
    """
    total_risk = 0
    output_lines = []
    section_entropy = {}  # Cache entropy values to avoid recalculation
    
    # Load config once
    cfg = PACKER_DETECTION_CONFIG
    flag_cfg = cfg['section_flags']
    high_ent_threshold = cfg['entropy_thresholds']['high_entropy']
    exec_entropy_threshold = cfg['entropy_thresholds'].get('executable_code_threshold', 6.0)

    # Print header
    console.print("\n[bold]Section Analysis[/bold]")
    console.print("=" * 85)
    console.print(f"{'Name':<12} {'Entropy':<10} {'Flags':<20} {'RawSize':<12} {'VirtSize':<12}")
    console.print("-" * 85)

    # First pass: calculate entropy and analyze each section
    for s in pe.sections:
        name = s.Name.rstrip(b"\x00").decode("utf-8", errors="replace")
        raw = s.SizeOfRawData
        virt = s.Misc_VirtualSize
        
        try:
            section_data = s.get_data()
            ent = calc_entropy_func(section_data)
            section_entropy[name] = ent  # Cache for second pass
        except Exception as e:
            console.print(f"[warning]Warning: Failed to analyze {name}: {str(e)}")
            ent = 0.0
            section_entropy[name] = ent

        flags = []
        
        if ent > high_ent_threshold:
            flags.append("High Entropy")
        if b"UPX" in s.Name:
            flags.append("UPX")
        if (s.Characteristics & flag_cfg['executable']):
            flags.append("X")
        if (s.Characteristics & flag_cfg['writable']):
            flags.append("W")
        if (s.Characteristics & flag_cfg['readable']):
            flags.append("R")
        if virt > raw * cfg['virtualsize_multiplier'] and ent > cfg['virtualsize_unpacking_threshold']:
            flags.append("VRaw Mismatch")

        flag_str = ", ".join(flags) if flags else "—"
        
        # Print row without Risk column (removed)
        console.print(f"{name:<12} {ent:<10.2f} {flag_str:<20} {raw:<12} {virt:<12}")

        output_lines.append(
            f"{name}: Entropy={ent:.2f}, Flags={flag_str}, RawSize={raw}, VirtSize={virt}"
        )

    console.print("-" * 85)
    
    # Second pass: detailed warnings using cached entropy values
    for s in pe.sections:
        name = s.Name.rstrip(b"\x00").decode("utf-8", errors="replace")
        ent = section_entropy.get(name, 0.0)
        
        # Warn about executable sections with elevated entropy (lower threshold for code)
        if (s.Characteristics & flag_cfg['executable']) and ent > exec_entropy_threshold:
            console.print(f"[!] {name} entropy ({ent:.2f}) is elevated for code section - may indicate packing/obfuscation")
        # Warn about non-standard sections with very high entropy
        elif ent > 7.4 and name not in [".text", ".data", ".rsrc", ".rdata"]:
            console.print(f"[!] {name} entropy ({ent:.2f}) is unusually high - possible encrypted payload")

    return total_risk, output_lines
