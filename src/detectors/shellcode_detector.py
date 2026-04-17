"""
Shellcode Pattern Detection
Detects common shellcode patterns: call/pop, API resolution loops, NOP sleds, ROP gadgets, heap spray
"""

import re
import pefile
from typing import Dict, List, Tuple, Any
from rich.console import Console
from src.detectors.common import safe_extract_strings
from config.shellcode_detection_config import SHELLCODE_CONFIG, SHELLCODE_PATTERNS, MEMORY_INJECTION_PATTERNS


# Shellcode signature patterns are now defined in config.py - see SHELLCODE_PATTERNS


def detect_shellcode(pe: pefile.PE, console: Console) -> Tuple[Dict, List[str]]:
    """
    Detect shellcode patterns in binary
    
    Args:
        pe: Pefile object
        console: Rich console for output
        
    Returns:
        Tuple of (detection_dict, output_lines)
    """
    output_lines = []
    results = {
        "call_pop_gadgets": [],
        "nop_sleds": [],
        "api_resolution_loops": [],
        "rop_gadgets": [],
        "heap_spray_patterns": [],
        "suspicious_opcodes": [],
        "injected_sections": [],
        "memory_injection_apis": [],
        "injection_chains_detected": [],
        "total_found": 0,
        "severity": "LOW",
        "sophistication": "NONE",
        "details": ""
    }
    
    try:
        all_strings = safe_extract_strings(pe)
        from src.utils.extraction import extract_all_binary_data
        binary_data = extract_all_binary_data(pe)
        
        # Check for call/pop patterns (delta addressing)
        call_pop = _check_call_pop_gadgets(binary_data, all_strings)
        results["call_pop_gadgets"] = call_pop["found"]
        
        # Check for NOP sleds
        nop_sleds = _check_nop_sleds(binary_data)
        results["nop_sleds"] = nop_sleds["found"]
        
        # Check for API resolution patterns
        api_resolution = _check_api_resolution_loops(all_strings)
        results["api_resolution_loops"] = api_resolution["found"]
        
        # Check for ROP gadgets
        rop_gadgets = _check_rop_gadgets(all_strings)
        results["rop_gadgets"] = rop_gadgets["found"]
        
        # Check for heap spray patterns
        heap_spray = _check_heap_spray_patterns(all_strings)
        results["heap_spray_patterns"] = heap_spray["found"]
        
        # Check for suspicious opcodes
        suspicious_ops = _check_suspicious_opcodes(binary_data)
        results["suspicious_opcodes"] = suspicious_ops["found"]
        
        # Check for memory injection APIs (from MEMORY_INJECTION_PATTERNS config)
        memory_injection = _check_memory_injection_apis(pe)
        results["memory_injection_apis"] = memory_injection["detected_apis"]
        results["injection_chains_detected"] = memory_injection["injection_chains"]
        
        # Check for injected sections (low entropy, weird perms)
        injected = _check_injected_sections(pe)
        results["injected_sections"] = injected["found"]
        
        results["total_found"] = (
            len(results["call_pop_gadgets"]) +
            len(results["nop_sleds"]) +
            len(results["api_resolution_loops"]) +
            len(results["rop_gadgets"]) +
            len(results["heap_spray_patterns"]) +
            len(results["suspicious_opcodes"]) +
            len(results["injected_sections"])
        )
        
        # Determine sophistication level
        sophistication_threshold_advanced = SHELLCODE_CONFIG['sophistication_thresholds']['advanced']
        sophistication_threshold_intermediate = SHELLCODE_CONFIG['sophistication_thresholds']['intermediate']
        min_total_threshold = SHELLCODE_CONFIG['min_total_found_threshold']
        
        if results["total_found"] >= sophistication_threshold_advanced:
            results["sophistication"] = "ADVANCED"
        elif results["total_found"] >= sophistication_threshold_intermediate:
            results["sophistication"] = "INTERMEDIATE"
        elif results["total_found"] > 0:
            results["sophistication"] = "BASIC"
        
        # Generate output
        if results["total_found"] > 0:
            console.print(f"\n[bold cyan]Shellcode Patterns Detection[/bold cyan]")
            console.print(f"[yellow]Sophistication Level: {results['sophistication']}[/yellow]\n")
            output_lines.append(f"[red]Shellcode Patterns Detected ({results['sophistication']})[/red]")
            
            if results["call_pop_gadgets"]:
                console.print(f"  [red]Call/Pop Gadgets[/red]: {len(results['call_pop_gadgets'])} found [dim](from shellcode_detection.py)[/dim]")
                console.print(f"    [dim]Detection: Regex pattern matching for delta addressing (call $+5 opcodes)[/dim]")
                output_lines.append(f"  [red]Call/Pop Gadgets[/red]: {len(results['call_pop_gadgets'])} found (from shellcode_detection.py)")
                for gadget in results["call_pop_gadgets"][:2]:
                    console.print(f"    - {gadget}")
                    output_lines.append(f"    - {gadget}")
            
            if results["nop_sleds"]:
                console.print(f"  [yellow]NOP Sleds[/yellow]: {len(results['nop_sleds'])} regions (possible code cave) [dim](from shellcode_detection.py)[/dim]")
                console.print(f"    [dim]Detection: Binary pattern matching (0x90 and 0xCC repetition) in .text section[/dim]")
                output_lines.append(f"  [yellow]NOP Sleds[/yellow]: {len(results['nop_sleds'])} regions (possible code cave) (from shellcode_detection.py)")
            
            if results["api_resolution_loops"]:
                console.print(f"  [red]API Resolution[/red]: {len(results['api_resolution_loops'])} patterns [dim](from shellcode_detection.py)[/dim]")
                console.print(f"    [dim]Detection: Keyword matching (LoadLibraryA, GetProcAddress) in binary strings[/dim]")
                output_lines.append(f"  [red]API Resolution[/red]: {len(results['api_resolution_loops'])} patterns (from shellcode_detection.py)")
                for api in results["api_resolution_loops"][:2]:
                    console.print(f"    - {api}")
                    output_lines.append(f"    - {api}")
            
            if results["rop_gadgets"]:
                console.print(f"  [yellow]ROP Gadgets[/yellow]: {len(results['rop_gadgets'])} found [dim](from shellcode_detection.py)[/dim]")
                console.print(f"    [dim]Detection: Opcode sequence scanning in .text/.code sections[/dim]")
                output_lines.append(f"  [yellow]ROP Gadgets[/yellow]: {len(results['rop_gadgets'])} found (from shellcode_detection.py)")
            
            if results["heap_spray_patterns"]:
                console.print(f"  [yellow]Heap Spray[/yellow]: {len(results['heap_spray_patterns'])} indicators [dim](from shellcode_detection.py)[/dim]")
                console.print(f"    [dim]Detection: Pattern matching (VirtualAlloc, FillMemory, RtlFillMemory)[/dim]")
                output_lines.append(f"  [yellow]Heap Spray[/yellow]: {len(results['heap_spray_patterns'])} indicators (from shellcode_detection.py)")
            
            if results["injected_sections"]:
                console.print(f"  [red]Suspicious Sections[/red]: {len(results['injected_sections'])} [dim](from shellcode_detection.py)[/dim]")
                console.print(f"    [dim]Detection: Section entropy and characteristics analysis[/dim]")
                output_lines.append(f"  [red]Suspicious Sections[/red]: {len(results['injected_sections'])} (from shellcode_detection.py)")
                for section in results["injected_sections"]:
                    console.print(f"    - {section}")
                    output_lines.append(f"    - {section}")
        else:
            console.print(f"[green][OK] No shellcode patterns detected[/green]\n")
            output_lines.append("[green][OK][/green] No shellcode patterns detected")
        
        results["details"] = "\n".join(output_lines)
        
    except Exception as e:
        output_lines.append(f"[yellow][!] Shellcode detection error: {str(e)[:100]}[/yellow]")
        results["details"] = "\n".join(output_lines)
    
    return results, output_lines


def _check_call_pop_gadgets(binary_data: bytes, strings: List[str]) -> Dict[str, Any]:
    """Detect call/pop patterns (delta addressing for position-independent code)"""
    found = []
    risk = 0
    
    # Look for call $+5 pattern from config
    call_pop_pattern = SHELLCODE_PATTERNS['call_pop_patterns'][0]
    if call_pop_pattern in binary_data:
        count = binary_data.count(call_pop_pattern)
        found.append(f"Delta addressing pattern (call $+5): {count} occurrence(s)")
    
    # Look for variations and followed by pop
    patterns = SHELLCODE_PATTERNS['call_pop_pop_patterns']
    
    for pattern, desc in patterns:
        if pattern in binary_data:
            found.append(f"PIC gadget: {desc}")
    
    return {"found": found, "risk": risk}


def _check_nop_sleds(binary_data: bytes) -> Dict[str, Any]:
    """Detect NOP sled regions (common in shellcode)"""
    found = []
    
    # Check for 0x90 (NOP) sleds
    nop_pattern = b"\x90" * SHELLCODE_PATTERNS['nop_sled_min_length']
    if nop_pattern in binary_data:
        # Count regions
        offset = 0
        sled_count = 0
        while True:
            offset = binary_data.find(nop_pattern, offset)
            if offset == -1:
                break
            # Measure sled length
            sled_len = 0
            pos = offset
            while pos < len(binary_data) and binary_data[pos] == 0x90:
                sled_len += 1
                pos += 1
            
            if sled_len >= SHELLCODE_PATTERNS['nop_sled_min_length']:
                found.append(f"NOP sled at offset 0x{offset:x} ({sled_len} bytes)")
                sled_count += 1
            
            offset += 1
            if sled_count > SHELLCODE_PATTERNS['nop_sled_report_limit']:  # Limit to config
                break
    
    # Check for INT3 sleds (0xcc) - also common in shellcode
    if SHELLCODE_PATTERNS['int3_sled_pattern'] in binary_data:
        found.append("INT3 sled detected (breakpoint pattern)")
    
    return {"found": found}


def _check_api_resolution_loops(strings: List[str]) -> Dict[str, Any]:
    """Detect API resolution patterns (dynamic import resolution)"""
    found = []
    
    api_apis = SHELLCODE_PATTERNS['api_resolution_apis']
    kernel_refs = SHELLCODE_PATTERNS['kernel_references']
    api_threshold_high = SHELLCODE_PATTERNS['api_resolution_threshold_high']
    api_threshold_low = SHELLCODE_PATTERNS['api_resolution_threshold_low']
    
    # Normalize strings once for performance (avoid repeated .lower() calls)
    strings_lower = [s.lower() for s in strings]
    api_apis_lower = [api.lower() for api in api_apis]
    kernel_refs_lower = [ref.lower() for ref in kernel_refs]
    
    api_count = 0
    for api_lower in api_apis_lower:
        for string_lower in strings_lower:
            if api_lower in string_lower:
                api_count += 1
                if api_lower not in found:
                    found.append(api_lower)
                break  # Found this API, move to next
    
    # If multiple resolution APIs, likely dynamic resolution
    if api_count >= api_threshold_high:
        found.append("Dynamic API resolution pattern")
    elif api_count >= api_threshold_low:
        pass
    
    # Check for kernel32 references (common in shellcode)
    for kernel_ref_lower in kernel_refs_lower:
        for string_lower in strings_lower:
            if kernel_ref_lower in string_lower:
                if kernel_ref_lower not in found:
                    found.append(f"Kernel reference: {kernel_ref_lower}")
                break  # Found this reference, move to next
    
    return {"found": found}


def _check_rop_gadgets(strings: List[str]) -> Dict[str, Any]:
    """Detect ROP (Return-Oriented Programming) gadget patterns"""
    found = []
    
    rop_indicators = SHELLCODE_PATTERNS['rop_indicators']
    max_string_length = SHELLCODE_PATTERNS['rop_string_max_length']
    
    for string in strings:
        for pattern in rop_indicators:
            if re.search(pattern, string, re.IGNORECASE):
                if string not in found and len(string) < max_string_length:
                    found.append(string)
    
    return {"found": found}


def _check_heap_spray_patterns(strings: List[str]) -> Dict[str, Any]:
    """Detect heap spray attack patterns"""
    found = []
    risk = 0
    
    spray_indicators = SHELLCODE_PATTERNS['heap_spray_indicators']
    
    for indicator in spray_indicators:
        for string in strings:
            if indicator.lower() in string.lower():
                if indicator not in found:
                    found.append(indicator)
    
    return {"found": found}


def _check_suspicious_opcodes(binary_data: bytes) -> Dict[str, Any]:
    """Detect suspicious opcode sequences"""
    found = []
    
    # Check for common shellcode opcodes from config
    suspicious_patterns = SHELLCODE_PATTERNS['suspicious_opcodes']
    opcode_threshold = SHELLCODE_PATTERNS['suspicious_opcode_threshold']
    
    for opcode, desc in suspicious_patterns:
        count = binary_data.count(opcode)
        if count > opcode_threshold:  # More than threshold occurrences is unusual
            found.append(f"{desc}: {count} times")
    
    return {"found": found}


def _check_injected_sections(pe: pefile.PE) -> Dict[str, Any]:
    """Check for suspicious/injected code sections"""
    found = []
    
    try:
        section_exec_flag = SHELLCODE_PATTERNS['section_exec_flag']
        section_write_flag = SHELLCODE_PATTERNS['section_write_flag']
        size_ratio_threshold = SHELLCODE_PATTERNS['section_size_ratio_threshold']
        
        for section in pe.sections:
            section_name = section.name.decode().strip("\x00")
            
            # Check for unusual permissions
            if section.Characteristics & section_exec_flag:  # Execute
                if section.Characteristics & section_write_flag:  # Write
                    # Writable and executable = suspicious
                    found.append(f"{section_name} (WX permissions)")
            
            # Check for unusual sizes or low entropy (potential encrypted/packed code)
            if section.VirtualSize > 0 and section.SizeOfRawData > 0:
                ratio = section.VirtualSize / section.SizeOfRawData
                if ratio > size_ratio_threshold:  # Highly compressed/packed
                    found.append(f"{section_name} (high virtual:raw ratio {ratio:.1f})")
    except Exception:
        pass  # Continue even if section analysis fails
    
    return {"found": found}


def _check_memory_injection_apis(pe: pefile.PE) -> Dict[str, Any]:
    """
    Detect memory injection and code injection APIs.
    Uses MEMORY_INJECTION_PATTERNS from config.
    
    Returns:
        Dict with detected_apis and risk_score
    """
    detected_apis = []
    injection_chains = []
    
    try:
        # Get injection API categories from config
        if not MEMORY_INJECTION_PATTERNS:
            return {"detected_apis": [], "injection_chains": [], "risk": 0}
        
        injection_config = MEMORY_INJECTION_PATTERNS
        
        # Build complete list of all injection APIs from config
        all_injection_apis = []
        for category, apis in injection_config['injection_apis'].items():
            all_injection_apis.extend(apis)
        
        # Check imported functions against injection APIs from config
        imported_apis = set()
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for dll in pe.DIRECTORY_ENTRY_IMPORT:
                for func in dll.imports:
                    if func.name:
                        func_name = func.name.decode('utf-8', errors='ignore')
                        if func_name in all_injection_apis:
                            imported_apis.add(func_name)
                            detected_apis.append(func_name)
        
        # Check for injection chains defined in config
        if len(detected_apis) >= 2:
            for chain in injection_config['injection_chains'].values():
                chain_found = sum(1 for api in chain if api in imported_apis)
                if chain_found >= 2:  # At least 2 APIs in chain detected
                    injection_chains.append(f"Partial injection chain detected ({chain_found} of {len(chain)} APIs)")
        
        return {
            "detected_apis": detected_apis,
            "injection_chains": injection_chains,
            "risk": 0
        }
    except Exception as e:
        return {"detected_apis": [], "injection_chains": [], "risk": 0}
    return {"found": found, "risk": risk}
