# imports.py
"""
Import Analysis Module

Analyzes imported functions from DLLs and classifies them by risk:
- CRITICAL: Process injection, memory manipulation, code execution
- SUSPICIOUS: Cryptography, hooking, dynamic loading
- MEDIUM: System interaction, file operations
- LOW: Standard library functions

This identifies potential malware behavior patterns through API usage.
"""

import pefile
from typing import Tuple, List, Any
from config.imports_config import IMPORT_ANALYSIS_KEYWORDS


def analyze_imports(pe: pefile.PE, console: Any) -> Tuple[bool, List[str], dict]:
    """
    Analyze PE imports and classify by risk category.
    
    Examines all imported Windows APIs and categorizes them based on
    malware behavior patterns (injection, persistence, C2, etc.).
    
    Args:
        pe: pefile.PE object representing the PE file
        console: Rich Console for formatted output
    
    Returns:
        Tuple[bool, List[str], dict]: (found_suspicious_api, output_lines, dll_imports)
            - found_suspicious_api: True if any suspicious/critical APIs found
            - output_lines: List of analysis output lines
            - dll_imports: Dict with all imported functions per DLL
    
    Classification levels:
        - CRITICAL: Injection/code execution (VirtualAllocEx, CreateRemoteThread, etc.)
        - SUSPICIOUS: Crypto, hooking, dynamic loading (LoadLibrary, CryptEncrypt, etc.)
        - MEDIUM: System access (RegOpenKey, CreateFile, etc.)
        - LOW: Safe standard library functions
    
    Example:
        >>> found_sus, lines, dlls = analyze_imports(pe, console)
        >>> if found_sus:
        ...     print("Malicious APIs detected!")
    """
    console.print("\n[bold cyan]Imported DLLs & Functions[/bold cyan]")
    found_suspicious_api = False
    output_lines = []
    dll_imports = {}  # Initialize here to return even if no imports

    # Convert to sets for O(1) lookup performance
    critical_keywords = set(IMPORT_ANALYSIS_KEYWORDS['critical_apis'])
    suspicious_keywords = set(IMPORT_ANALYSIS_KEYWORDS['suspicious_apis'])
    moderate_keywords = set(IMPORT_ANALYSIS_KEYWORDS['moderate_apis'])
    anti_debug_keywords = set(IMPORT_ANALYSIS_KEYWORDS['anti_debug_apis'])
    rat_keywords = set(IMPORT_ANALYSIS_KEYWORDS['rat_apis'])

    # System DLLs whitelist (moved to config)
    benign_dlls = set(IMPORT_ANALYSIS_KEYWORDS['benign_dlls'])

    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        # Group imports by DLL for better organization
        dll_imports = {}
        suspicious_apis_found = {}
        
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll = entry.dll.decode(errors="replace")
            dll_upper = dll.upper()
            dll_imports[dll] = []
            suspicious_apis_found[dll] = []

            for imp in entry.imports:
                name = imp.name.decode(errors="replace") if imp.name else f"ORD_{imp.ordinal}"
                dll_imports[dll].append(name)

                # Check if API is suspicious
                name_lower = name.lower()
                
                if any(k in name_lower for k in critical_keywords):
                    found_suspicious_api = True
                    suspicious_apis_found[dll].append(name)
                elif any(k in name_lower for k in suspicious_keywords):
                    found_suspicious_api = True
                    suspicious_apis_found[dll].append(name)
                elif any(k in name_lower for k in anti_debug_keywords):
                    found_suspicious_api = True
                    suspicious_apis_found[dll].append(name)
                elif any(k in name_lower for k in rat_keywords):
                    found_suspicious_api = True
                    suspicious_apis_found[dll].append(name)
                elif any(k in name_lower for k in moderate_keywords) and dll_upper not in benign_dlls:
                    found_suspicious_api = True
                    suspicious_apis_found[dll].append(name)
        
        # Display suspicious APIs first (abbreviated), then summary of benign imports
        max_display_per_dll = 5  # Show first N suspicious APIs per DLL
        has_displayed_anything = False
        
        # Priority 1: Display suspicious APIs
        for dll, suspicious_apis in suspicious_apis_found.items():
            if suspicious_apis:
                console.print(f"\n[bold red][SUSPICIOUS] {dll}[/bold red]")
                output_lines.append(f"\n[SUSPICIOUS] {dll}")
                for api in suspicious_apis[:max_display_per_dll]:
                    console.print(f"   [red]• {api}[/red]")
                    output_lines.append(f"  • {api}")
                if len(suspicious_apis) > max_display_per_dll:
                    console.print(f"   [dim]... and {len(suspicious_apis) - max_display_per_dll} more[/dim]")
                    output_lines.append(f"  ... and {len(suspicious_apis) - max_display_per_dll} more")
                has_displayed_anything = True
        
        # Priority 2: Summary of major system/benign DLLs
        console.print(f"\n[dim][Standard Libraries Summary][/dim]")
        output_lines.append(f"\n[Standard Libraries Summary]")
        for dll, imports in dll_imports.items():
            if dll not in suspicious_apis_found or not suspicious_apis_found[dll]:
                # Only show summary for non-suspicious DLLs
                console.print(f"[cyan]{dll}[/cyan]: {len(imports)} functions")
                output_lines.append(f"{dll}: {len(imports)} functions")
    else:
        console.print("[red]No import table — file likely packed[/red]")
        output_lines.append("No import table")

    return found_suspicious_api, output_lines, dll_imports

