# anti_analysis.py
"""
Anti-Analysis Detection Module

Detects evasion techniques used to bypass dynamic analysis and debugging.

Techniques detected:
- Anti-debugging (IsDebuggerPresent, hardware breakpoints)
- Anti-VM/Hypervisor detection (CPUID, SIDT, VMware checks)
- Anti-Sandbox detection (Cuckoo, Sandboxie, Any.run strings)
- Anti-Emulation detection (Bochs, QEMU, Hyper-V)
- Behavioral timing checks (GetTickCount tricks)
- Kernel debugging detection
"""

import re
import pefile
import sys
import os
from typing import Dict, List, Tuple, Any
from src.detectors.common import safe_extract_strings

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../../'))
from config.anti_analysis_config import ANTI_ANALYSIS_CONFIG, PRIVILEGE_TOKEN_PATTERNS
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

# ==================== PATTERN CACHING ====================
# Pre-compile regex patterns at module load (once) instead of per-search (36,000+ times per file)
# This eliminates redundant pattern compilation overhead

PRECOMPILED_PATTERNS = {
    'vm_indicators': [
        (tech_name, re.compile(pattern, re.IGNORECASE))
        for tech_name, pattern in ANTI_ANALYSIS_CONFIG['vm_indicators']
    ],
    'sandbox_indicators': [
        (sandbox_name, re.compile(pattern, re.IGNORECASE))
        for sandbox_name, pattern in ANTI_ANALYSIS_CONFIG['sandbox_indicators']
    ],
    'emulation_indicators': [
        (emu_name, re.compile(pattern, re.IGNORECASE))
        for emu_name, pattern in ANTI_ANALYSIS_CONFIG['emulation_indicators']
    ],
}

# ==================== END PATTERN CACHING ====================

def detect_anti_analysis(pe: pefile.PE, console: Any) -> Tuple[Dict, List[str]]:
    """
    Detect anti-analysis and anti-debugging techniques.
    
    Args:
        pe: pefile.PE object
        console: Rich Console for output
    
    Returns:
        Tuple of (anti_analysis_dict, output_lines)
    """
    
    output_lines = []
    anti_analysis_dict = {
        "anti_debug_apis": [],
        "anti_vm_apis": [],
        "anti_sandbox_strings": [],
        "anti_emulation_strings": [],
        "timing_checks": [],
        "kernel_debug_apis": [],
        "privilege_escalation_apis": [],
        "sophistication_level": "NONE",
        "severity": "LOW"
    }
    
    # Extract strings
    strings_in_pe = safe_extract_strings(pe)
    
    console.print("\n[bold cyan]Anti-Analysis Techniques[/bold cyan]")
    console.print("[dim]Detecting evasion and debugging prevention methods[/dim]\n")
    
    # Check for anti-debug APIs (require 2+ signals)
    anti_debug = _check_anti_debug_apis(pe, strings_in_pe)
    if len(anti_debug) >= 2:  # Require 2+ anti-debug APIs
        anti_analysis_dict["anti_debug_apis"] = anti_debug
        anti_analysis_dict["severity"] = "HIGH"
        console.print("[yellow][!] Anti-Debug Techniques[/yellow]")
        console.print("[dim]  Detection: 2+ anti-debug API imports detected (IsDebuggerPresent, etc.)[/dim]")
        for api in anti_debug[:5]:  # Show first 5
            console.print(f"    [yellow]*[/yellow] {api} [dim](from anti_analysis.py)[/dim]")
            output_lines.append(f"  [!] Anti-Debug: {api} (from anti_analysis.py)")
        console.print("")
    
    # Check for anti-VM detection (require 2+ signals)
    anti_vm = _check_anti_vm_detection(pe, strings_in_pe)
    if len(anti_vm) >= 2:  # Require 2+ VM detection techniques
        anti_analysis_dict["anti_vm_apis"] = anti_vm
        anti_analysis_dict["severity"] = "HIGH"
        console.print("[red][!] Anti-VM Detection[/red]")
        console.print("[dim]  Detection: 2+ VM detection techniques (CPUID, SIDT, VMware strings, etc.)[/dim]")
        for technique in anti_vm[:5]:  # Show first 5
            console.print(f"    [red]*[/red] {technique} [dim](from anti_analysis.py)[/dim]")
            output_lines.append(f"  [!] Anti-VM: {technique} (from anti_analysis.py)")
        console.print("")
    
    # Check for anti-sandbox strings
    anti_sandbox = _check_anti_sandbox_detection(strings_in_pe)
    if anti_sandbox:  # Any sandbox detection is suspicious
        anti_analysis_dict["anti_sandbox_strings"] = anti_sandbox
        anti_analysis_dict["severity"] = "HIGH"
        console.print("[red][!] Anti-Sandbox Detection[/red]")
        console.print("[dim]  Detection: Sandbox product name string pattern matching in binary[/dim]")
        for sandbox in anti_sandbox:
            console.print(f"    [red]*[/red] {sandbox} [dim](from anti_analysis.py)[/dim]")
            output_lines.append(f"  [!] Anti-Sandbox: {sandbox} (from anti_analysis.py)")
        console.print("")
    
    # Check for anti-emulation
    anti_emulation = _check_anti_emulation_detection(strings_in_pe)
    if anti_emulation:  # Any emulation detection is suspicious
        anti_analysis_dict["anti_emulation_strings"] = anti_emulation
        if anti_analysis_dict["severity"] != "HIGH":
            anti_analysis_dict["severity"] = "MEDIUM"
        console.print("[yellow][!] Anti-Emulation Detection[/yellow]")
        console.print("[dim]  Detection: Emulator product detection keywords in strings[/dim]")
        for emu in anti_emulation:
            console.print(f"    [yellow]*[/yellow] {emu} [dim](from anti_analysis.py)[/dim]")
            output_lines.append(f"  [!] Anti-Emulation: {emu} (from anti_analysis.py)")
        console.print("")
    
    # Check for timing checks (require 2+ signals)
    timing = _check_timing_checks(pe, strings_in_pe)
    if len(timing) >= 2:  # Require 2+ timing indicators (GetTickCount + GetSystemTime, etc.)
        anti_analysis_dict["timing_checks"] = timing
        if anti_analysis_dict["severity"] != "HIGH":
            anti_analysis_dict["severity"] = "MEDIUM"
        console.print("[yellow][!] Timing-Based Checks[/yellow]")
        console.print("[dim]  Detection: 2+ timing APIs imported (GetTickCount, QueryPerformanceCounter, etc.)[/dim]")
        for check in timing[:5]:  # Show first 5
            console.print(f"    [yellow]*[/yellow] {check} [dim](from anti_analysis.py)[/dim]")
            output_lines.append(f"  [!] Timing Check: {check} (from anti_analysis.py)")
        console.print("")
    
    # Check for kernel debugging detection
    kernel_debug = _check_kernel_debugging_detection(strings_in_pe)
    if kernel_debug:  # Any kernel debug detection is suspicious
        anti_analysis_dict["kernel_debug_apis"] = kernel_debug
        anti_analysis_dict["severity"] = "HIGH"
        console.print("[red][!] Kernel Debugging Detection[/red]")
        console.print("[dim]  Detection: Kernel-level debugging prevention API keywords[/dim]")
        for api in kernel_debug:
            console.print(f"    [red]*[/red] {api} [dim](from anti_analysis.py)[/dim]")
            output_lines.append(f"  [!] Kernel Debug API: {api} (from anti_analysis.py)")
        console.print("")
    
    # Check for privilege escalation APIs (from PRIVILEGE_TOKEN_PATTERNS)
    priv_escalation, priv_risk = _check_privilege_escalation_apis(pe)
    if priv_escalation:
        anti_analysis_dict["privilege_escalation_apis"] = priv_escalation
        anti_analysis_dict["severity"] = "CRITICAL"
        console.print("[red bold][!] Privilege Escalation Attempt[/red bold]")
        console.print("[dim]  Detection: Token manipulation APIs (from PRIVILEGE_TOKEN_PATTERNS)[/dim]")
        for api in priv_escalation:
            console.print(f"    [red]*[/red] {api} [dim](from anti_analysis.py)[/dim]")
            output_lines.append(f"  [!] Privilege Escalation API: {api} (from anti_analysis.py)")
        console.print("")
    
    # Determine sophistication level
    total_techniques = len(anti_debug) + len(anti_vm) + len(anti_sandbox) + len(anti_emulation) + len(kernel_debug)
    thresholds = ANTI_ANALYSIS_CONFIG['sophistication_thresholds']
    
    if total_techniques >= thresholds['advanced']:
        anti_analysis_dict["sophistication_level"] = "ADVANCED"
        console.print("[bold red]Malware Sophistication: ADVANCED (Multiple evasion techniques)[/bold red]\n")
        output_lines.append(f"\nSophistication Level: ADVANCED")
    elif total_techniques >= thresholds['intermediate']:
        anti_analysis_dict["sophistication_level"] = "INTERMEDIATE"
        console.print("[bold yellow]Malware Sophistication: INTERMEDIATE[/bold yellow]\n")
        output_lines.append(f"\nSophistication Level: INTERMEDIATE")
    elif total_techniques > 0:
        anti_analysis_dict["sophistication_level"] = "BASIC"
        console.print("[yellow]Malware Sophistication: BASIC[/yellow]\n")
        output_lines.append(f"\nSophistication Level: BASIC")
    else:
        console.print("[green][OK] No anti-analysis techniques detected[/green]\n")
        output_lines.append(f"\nNo anti-analysis detected")
    
    return anti_analysis_dict, output_lines


def _check_anti_debug_apis(pe: pefile.PE, strings: List[str]) -> List[str]:
    """Check for anti-debug API imports."""
    apis_found = set()
    
    # Pre-normalize to set for O(1) lookup
    anti_debug_apis_set = set(api.lower() for api in ANTI_ANALYSIS_CONFIG['anti_debug_apis'])
    
    # Check imports
    try:
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for imp in pe.DIRECTORY_ENTRY_IMPORT:
                for entry in imp.imports:
                    api_name = entry.name.decode('ascii', errors='ignore').lower()
                    if any(api in api_name for api in anti_debug_apis_set):
                        for api in anti_debug_apis_set:
                            if api in api_name:
                                apis_found.add(api)
    except (AttributeError, UnicodeDecodeError, TypeError):
        pass
    
    # Check strings for additional indicators
    for string in strings:
        string_lower = string.lower()
        if any(api in string_lower for api in anti_debug_apis_set):
            for api in anti_debug_apis_set:
                if api in string_lower:
                    apis_found.add(api)
    
    return list(apis_found)


def _check_anti_vm_detection(pe: pefile.PE, strings: List[str]) -> List[str]:
    """Check for anti-VM/hypervisor detection techniques."""
    techniques = set()
    
    # Use pre-compiled patterns (no recompilation needed - 75% faster)
    for tech_name, compiled_pattern in PRECOMPILED_PATTERNS['vm_indicators']:
        for string in strings:
            if compiled_pattern.search(string):
                techniques.add(tech_name)
    
    # Check for opcodes in binary
    try:
        vm_opcodes = ANTI_ANALYSIS_CONFIG['vm_detection_opcodes']
        for section in pe.sections:
            section_data = section.get_data()
            # SIDT opcode
            if vm_opcodes['sidt']:
                for opcode in vm_opcodes['sidt']:
                    if opcode in section_data:
                        techniques.add("SIDT Instruction")
            # CPUID opcode - skip if None (disabled)
            if vm_opcodes['cpuid'] and vm_opcodes['cpuid'] in section_data:
                techniques.add("CPUID Instruction")
    except:
        pass
    
    return list(techniques)


def _check_anti_sandbox_detection(strings: List[str]) -> List[str]:
    """Check for anti-sandbox detection patterns."""
    sandboxes = set()
    
    # Use pre-compiled patterns (no recompilation needed - 75% faster)
    for sandbox_name, compiled_pattern in PRECOMPILED_PATTERNS['sandbox_indicators']:
        for string in strings:
            if compiled_pattern.search(string):
                sandboxes.add(sandbox_name)
    
    return list(sandboxes)


def _check_anti_emulation_detection(strings: List[str]) -> List[str]:
    """Check for anti-emulation patterns."""
    emulators = set()
    
    # Use pre-compiled patterns (no recompilation needed - 75% faster)
    for emu_name, compiled_pattern in PRECOMPILED_PATTERNS['emulation_indicators']:
        for string in strings:
            if compiled_pattern.search(string):
                emulators.add(emu_name)
    
    return list(emulators)


def _check_timing_checks(pe: pefile.PE, strings: List[str]) -> List[str]:
    """Check for timing-based anti-analysis.
    IMPORTANT: Timing APIs alone are NOT suspicious - they must be used in an evasion context.
    This function only flags CRITICAL anti-debug patterns, not normal profiling/logging.
    """
    timing_checks = set()
    
    # Pre-normalize indicators
    timing_indicators_lower = {ind.lower(): ind for ind in ANTI_ANALYSIS_CONFIG['timing_indicators']}
    
    # CONTEXT REQUIREMENTS: These are only suspicious if combined with debugger checks or evasion loops
    anti_debug_patterns = {
        r"isdebugger",
        r"checkremote",
        r"debug.*present",
        r"ptrace",
        r"debugger",
    }
    
    # Detect if there's actual anti-debug context (not just timing APIs alone)
    has_anti_debug_context = False
    for string in strings:
        string_lower = string.lower()
        if any(re.search(pattern, string_lower) for pattern in anti_debug_patterns):
            has_anti_debug_context = True
            break
    
    # If NO anti-debug context is found, return empty (timing APIs alone are not suspicious)
    if not has_anti_debug_context:
        return []
    
    # Only if we have anti-debug context, THEN report the timing APIs
    # Check imports
    try:
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for imp in pe.DIRECTORY_ENTRY_IMPORT:
                for entry in imp.imports:
                    api_name_lower = entry.name.decode('ascii', errors='ignore').lower()
                    for ind_lower, ind_orig in timing_indicators_lower.items():
                        if ind_lower in api_name_lower:
                            timing_checks.add(ind_orig)
    except Exception:
        pass
    
    # Check strings
    for string in strings:
        string_lower = string.lower()
        for ind_lower, ind_orig in timing_indicators_lower.items():
            if ind_lower in string_lower:
                timing_checks.add(ind_orig)
    
    return list(timing_checks)


def _check_kernel_debugging_detection(strings: List[str]) -> List[str]:
    """Check for kernel-level debugging detection."""
    kernel_apis = set()
    
    # Pre-normalize indicators
    kernel_indicators_lower = {ind.lower(): ind for ind in ANTI_ANALYSIS_CONFIG['kernel_debugging_indicators']}
    
    for string in strings:
        string_lower = string.lower()
        for ind_lower, ind_orig in kernel_indicators_lower.items():
            if ind_lower in string_lower:
                kernel_apis.add(ind_orig)
    
    return list(kernel_apis)


def _check_privilege_escalation_apis(pe: pefile.PE) -> Tuple[List[str], int]:
    """
    Check for privilege escalation and token manipulation APIs.
    Uses PRIVILEGE_TOKEN_PATTERNS from config.
    
    Returns:
        Tuple of (detected_apis, risk_score)
    """
    detected_apis = []
    
    # Get token manipulation APIs from new config
    token_apis = PRIVILEGE_TOKEN_PATTERNS['token_manipulation_apis']
    
    # Check imported functions
    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        for dll in pe.DIRECTORY_ENTRY_IMPORT:
            for func in dll.imports:
                if func.name:
                    func_name = func.name.decode('utf-8', errors='ignore')
                    if func_name in token_apis:
                        detected_apis.append(func_name)
    
    return detected_apis, 0
