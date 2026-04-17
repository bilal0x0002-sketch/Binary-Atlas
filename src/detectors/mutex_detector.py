# mutex_signatures.py
"""
Mutex Signature Detection Module

Detects known malware mutex patterns for family clustering and identification.

Known malware mutex signatures:
- Emotet, Mirai, TrickBot, Qakbot, etc.
- Single-instance behavior indicators
"""

import re
import pefile
from typing import Dict, List, Tuple, Any
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))
from config.mutex_signatures_config import MUTEX_CONFIG
from src.utils.extraction import extract_all_strings

# Configuration imported from config.py - see MUTEX_CONFIG


def detect_mutex_signatures(pe: pefile.PE, console: Any) -> Tuple[Dict, List[str]]:
    """
    Detect mutex signatures and patterns in PE file.
    
    Args:
        pe: pefile.PE object
        console: Rich Console for output
    
    Returns:
        Tuple of (mutex_dict, output_lines)
    """
    
    output_lines = []
    mutex_dict = {
        "known_families": [],
        "suspicious_mutexes": [],
        "all_mutexes": [],
        "malware_confidence": "UNKNOWN",
        "severity": "LOW"
    }
    
    # Extract strings
    try:
        strings_in_pe = extract_all_strings(pe)
    except Exception:
        strings_in_pe = []  # Continue with empty list if extraction fails
    
    # Check imports - THIS IS THE KEY: Only proceed if mutex APIs are found
    mutex_apis = _check_mutex_apis(pe)
    
    console.print("\n[bold cyan]Mutex Analysis[/bold cyan]")
    console.print("[dim]Detecting mutex patterns and malware families[/dim]\n")
    
    # If no mutex APIs found, just skip the analysis entirely
    if not mutex_apis["found"]:
        console.print("[green][OK] No mutex creation APIs found[/green]\n")
        return mutex_dict, output_lines
    
    # Show mutex APIs
    console.print("[yellow][!] Mutex Handling APIs[/yellow]")
    console.print("[dim]  Detection: Mutex creation API imports in import table[/dim]")
    for api in sorted(set(mutex_apis["apis"])):  # Deduplicate and sort
        console.print(f"    [yellow]*[/yellow] {api} [dim](from mutex_signatures.py)[/dim]")
        output_lines.append(f"  [!] Mutex API: {api} (from mutex_signatures.py)")
    console.print("")
    
    # Extract potential mutexes ONLY if mutex APIs are found (indicates actual mutex usage)
    all_mutexes = _extract_mutexes(strings_in_pe)
    
    # Check for known malware families
    family_matches = _check_malware_families(all_mutexes)
    
    if family_matches:
        mutex_dict["known_families"] = family_matches
        mutex_dict["severity"] = "CRITICAL"
        mutex_dict["malware_confidence"] = "CRITICAL"
        console.print("[bold red][!] Known Malware Family Detected[/bold red]")
        console.print("[dim]  Detection: Mutex string pattern matching against known malware signatures[/dim]")
        for family, mutexes in family_matches.items():
            console.print(f"    [red]*[/red] {family}: {mutexes[0]} [dim](from mutex_signatures.py)[/dim]")
            output_lines.append(f"  [CRITICAL] Known family {family}: {mutexes[0]} (from mutex_signatures.py)")
        console.print("")
    
    # Check for suspicious patterns
    suspicious = _check_suspicious_patterns(all_mutexes)
    
    # STRICT filtering: Only report if we found actual known malware families or
    # very high-confidence suspicious patterns. Don't pollute with weak signals.
    if suspicious:
        # Only keep patterns with meaningful hit count (3+ matches = actual pattern)
        filtered_suspicious = {
            pattern: mutexes for pattern, mutexes in suspicious.items()
            if len(mutexes) >= 3  # Only report patterns found 3+ times
        }
        
        if filtered_suspicious:
            mutex_dict["suspicious_mutexes"] = filtered_suspicious
            if mutex_dict["severity"] != "CRITICAL":
                mutex_dict["severity"] = "MEDIUM"  # Lower severity than known families
            console.print("[yellow][!] Suspicious Mutex Patterns[/yellow]")
            console.print("[dim]  Detection: Obfuscation pattern matching (high-entropy, UUID-like)[/dim]")
            for pattern_type, mutexes in filtered_suspicious.items():
                for mutex in list(set(mutexes))[:1]:  # Show only first hit per pattern
                    console.print(f"    [yellow]*[/yellow] [{pattern_type}] {mutex} [dim](from mutex_signatures.py)[/dim]")
                    output_lines.append(f"  [!] {pattern_type}: {mutex} (from mutex_signatures.py)")
            console.print("")
    
    # Confidence assessment
    if family_matches:
        console.print("[bold red]Malware Confidence: CRITICAL (Known family)[/bold red]\n")
        output_lines.append(f"\nMutex Confidence: CRITICAL (Known malware family)")
    elif suspicious:
        console.print("[bold yellow]Malware Confidence: MEDIUM (Suspicious patterns + mutex APIs)[/bold yellow]\n")
        output_lines.append(f"\nMutex Confidence: MEDIUM (Suspicious patterns detected)")
    elif all_mutexes:
        # Found mutex APIs but no suspicious patterns - just note the API usage
        console.print("[yellow]Mutex APIs present but patterns are normal[/yellow]\n")
        output_lines.append(f"\nMutex count: {len(all_mutexes)}")
    
    return mutex_dict, output_lines


def _check_mutex_apis(pe: pefile.PE) -> Dict:
    """Check for mutex-related API imports."""
    findings = {
        "found": False,
        "apis": []
    }
    
    mutex_apis = MUTEX_CONFIG['mutex_apis']
    
    try:
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for imp in pe.DIRECTORY_ENTRY_IMPORT:
                for entry in imp.imports:
                    api_name = entry.name.decode('ascii', errors='ignore')
                    if api_name in mutex_apis:
                        findings["found"] = True
                        findings["apis"].append(api_name)
    except (AttributeError, UnicodeDecodeError, TypeError):
        pass
    
    return findings


def _extract_mutexes(strings: List[str]) -> List[str]:
    """Extract potential mutex names from strings.
    
    STRICT filtering:
    - Must match named object pattern (Global\*, Local\*, Session*)
    - Must NOT be common API/CRT names (filters garbage)
    - Must look like an actual mutex name (hex or meaningful words)
    
    The key insight: Most strings in a binary are NOT mutexes.
    A real mutex is:
    - Named object reference (Global\name or Local\name)
    - Random-looking identifier (high entropy short string)
    - Known malware pattern
    
    NOT a real mutex:
    - API function name (CreateMutexW, EnterCriticalSection)
    - CRT exception name (bad_alloc, exception)
    - GUI function name (DispatchMessageW, SetWindowText)
    - Compiler artifact (MSVC string)
    """
    mutexes = set()
    
    mutex_patterns = MUTEX_CONFIG['mutex_extraction_patterns']
    min_length = MUTEX_CONFIG['min_mutex_length']
    
    # Common API/CRT names to exclude (not actual mutexes)
    false_positive_keywords = {
        'loadlibrary', 'getprocaddress', 'createprocess', 'enumresources',
        'entercritical', 'leavecritical', 'initializedebug', 'dllmain',
        'exception', 'bad_alloc', 'out_of_range', 'runtime_error',
        'locale', 'codecvt', 'ctype', 'collate', 'monetary', 'time',
        'messages', 'num_get', 'num_put', 'money_get', 'money_put',
        'inputstream', 'outputstream', 'iostream', 'fstream',
        'stringstream', 'wstring', 'vector', 'deque', 'list',
        '_beginthreadex', '_endthreadex', '_createthread',
        'critical_section', 'mutex_object', 'event_object',
        'waitforsingle', 'waitformultiple', 'setwindowtext',
        'getwindowtext', 'postmessage', 'sendmessage', 'wndproc',
        'dispatchmessage', 'translatemessage', 'isclass',
        'registercl', 'unregisterclass', 'defwindowproc',
        'createwindow', 'findwindow', 'getwindow', 'showwindow'
    }
    
    for string in strings:
        for pattern in mutex_patterns:
            matches = re.findall(pattern, string, re.IGNORECASE)
            for match in matches:
                if len(match) < min_length:
                    continue
                
                match_lower = match.lower()
                
                # Filter out obvious false positives
                is_false_positive = any(
                    keyword in match_lower 
                    for keyword in false_positive_keywords
                )
                if is_false_positive:
                    continue
                
                # Only keep if looks like actual mutex: hex + length, or known pattern
                # DO NOT just accept anything with letters
                has_hex = bool(re.search(r'[a-f0-9]{6,}', match_lower))
                has_uuid = bool(re.search(r'[a-f0-9]{8}-[a-f0-9]{4}', match_lower))
                
                # Accept if clearly named mutex pattern plus hex/uuid
                if has_hex or has_uuid:
                    mutexes.add(match)
    
    return list(mutexes)


def _check_malware_families(mutexes: List[str]) -> Dict[str, List[str]]:
    """Check for known malware family signatures."""
    families_found = {}
    
    malware_signatures = MUTEX_CONFIG['malware_signatures']
    
    for family, patterns in malware_signatures.items():
        for mutex in mutexes:
            for pattern in patterns:
                if re.search(pattern, mutex, re.IGNORECASE):
                    if family not in families_found:
                        families_found[family] = []
                    families_found[family].append(mutex)
    
    # Remove duplicates within each family
    for family in families_found:
        families_found[family] = list(set(families_found[family]))
    
    return families_found


def _check_suspicious_patterns(mutexes: List[str]) -> Dict[str, List[str]]:
    """Check for suspicious mutex patterns."""
    patterns_found = {}
    
    suspicious_patterns = MUTEX_CONFIG['suspicious_patterns']
    
    for pattern_name, pattern_regex in suspicious_patterns.items():
        for mutex in mutexes:
            if re.search(pattern_regex, mutex, re.IGNORECASE):
                if pattern_name not in patterns_found:
                    patterns_found[pattern_name] = []
                patterns_found[pattern_name].append(mutex)
    
    # Remove duplicates
    for pattern in patterns_found:
        patterns_found[pattern] = list(set(patterns_found[pattern]))
    
    return patterns_found
