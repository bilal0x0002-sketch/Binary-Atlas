# persistence_detection.py
"""
Persistence Detection Module

Detects how malware achieves persistence on Windows systems.

Common persistence mechanisms:
- Registry Run/RunOnce keys (auto-start on login)
- Service installation (Windows service execution)
- Scheduled tasks (Task Scheduler automation)
- Startup folder (user startup directory)
- WMI event subscriptions (asynchronous execution)
- Browser helper objects (IE automation)
- Logon scripts (Windows logon execution)
"""

import re
import pefile
from typing import Dict, List, Tuple, Any
from src.detectors.common import safe_extract_strings
from config.persistence_detection_config import PERSISTENCE_PATTERNS_CONFIG

def detect_persistence_mechanisms(pe: pefile.PE, console: Any) -> Tuple[Dict, List[str]]:
    """
    Detect persistence mechanisms in PE file.
    
    Args:
        pe: pefile.PE object
        console: Rich Console for output
    
    Returns:
        Tuple of (persistence_dict, output_lines)
    """
    
    output_lines = []
    persistence_dict = {
        "methods_found": [],
        "severity": "LOW",
        "is_persistent": False,
        "details": {}
    }
    
    # Extract all strings from PE
    try:
        strings_in_pe = safe_extract_strings(pe)
    except Exception:
        strings_in_pe = []  # Continue with empty list if extraction fails
    
    console.print("\n[bold cyan]Persistence Mechanisms[/bold cyan]")
    console.print("[dim]Detecting methods for maintaining presence on system[/dim]\n")
    
    # Check each persistence type
    registry_findings = _check_registry_persistence(strings_in_pe)
    service_findings = _check_service_persistence(strings_in_pe)
    task_findings = _check_scheduled_task_persistence(strings_in_pe)
    startup_findings = _check_startup_persistence(strings_in_pe)
    wmi_findings = _check_wmi_persistence(strings_in_pe)
    bho_findings = _check_bho_persistence(strings_in_pe)
    logon_findings = _check_logon_persistence(strings_in_pe)
    
    # Process registry findings
    if registry_findings["found"]:
        persistence_dict["methods_found"].append("Registry Run Keys")
        persistence_dict["details"]["registry_run"] = registry_findings
        console.print("[red][!] Registry Run Keys Detected[/red]")
        console.print(f"  [dim]Detection: Registry key pattern matching in strings[/dim]")
        for pattern in registry_findings["patterns"]:
            console.print(f"    [yellow]*[/yellow] {pattern} [dim](from persistence_detection.py)[/dim]")
            output_lines.append(f"  [!] Registry Run: {pattern} (from persistence_detection.py)")
        console.print("")
    
    # Process service findings
    if service_findings["found"]:
        persistence_dict["methods_found"].append("Service Installation")
        persistence_dict["details"]["service"] = service_findings
        console.print("[red][!] Service Installation Detected[/red]")
        console.print(f"  [dim]Detection: Service API imports (CreateServiceA/W, etc.) found in import table[/dim]")
        for api in service_findings["apis"]:
            console.print(f"    [red]*[/red] {api} [dim](from persistence_detection.py)[/dim]")
            output_lines.append(f"  [CRITICAL] Service API: {api} (from persistence_detection.py)")
        console.print("")
    
    # Process scheduled task findings
    if task_findings["found"]:
        persistence_dict["methods_found"].append("Scheduled Tasks")
        persistence_dict["details"]["scheduled_task"] = task_findings
        console.print("[red][!] Scheduled Task Detection[/red]")
        console.print(f"  [dim]Detection: String matching for scheduler APIs and keywords[/dim]")
        for indicator in task_findings["indicators"]:
            console.print(f"    [yellow]*[/yellow] {indicator} [dim](from persistence_detection.py)[/dim]")
            output_lines.append(f"  [!] Task Scheduler: {indicator} (from persistence_detection.py)")
        console.print("")
    
    # Process startup findings
    if startup_findings["found"]:
        persistence_dict["methods_found"].append("Startup Folder")
        persistence_dict["details"]["startup"] = startup_findings
        console.print("[red][!] Startup Folder References Detected[/red]")
        console.print(f"  [dim]Detection: String pattern matching for startup folder paths[/dim]")
        for pattern in startup_findings["patterns"]:
            console.print(f"    [yellow]*[/yellow] {pattern} [dim](from persistence_detection.py)[/dim]")
            output_lines.append(f"  [!] Startup: {pattern} (from persistence_detection.py)")
        console.print("")
    
    # Process WMI findings
    if wmi_findings["found"]:
        persistence_dict["methods_found"].append("WMI Event Subscriptions")
        persistence_dict["details"]["wmi"] = wmi_findings
        console.print("[red][!] WMI Persistence Indicators[/red]")
        console.print(f"  [dim]Detection: WMI keyword pattern matching in strings[/dim]")
        for indicator in wmi_findings["indicators"]:
            console.print(f"    [red]*[/red] {indicator} [dim](from persistence_detection.py)[/dim]")
            output_lines.append(f"  [CRITICAL] WMI: {indicator} (from persistence_detection.py)")
        console.print("")
    
    # Process BHO findings
    if bho_findings["found"]:
        persistence_dict["methods_found"].append("Browser Helper Objects")
        persistence_dict["details"]["bho"] = bho_findings
        console.print("[yellow][!] Browser Helper Object (BHO) Indicators[/yellow]")
        console.print(f"  [dim]Detection: Registry pattern and CLSID format matching[/dim]")
        for clsid in bho_findings["clsids"]:
            console.print(f"    [yellow]*[/yellow] CLSID: {clsid} [dim](from persistence_detection.py)[/dim]")
            output_lines.append(f"  [!] BHO: {clsid} (from persistence_detection.py)")
        console.print("")
    
    # Process logon script findings
    if logon_findings["found"]:
        persistence_dict["methods_found"].append("Logon Scripts")
        persistence_dict["details"]["logon_script"] = logon_findings
        console.print("[yellow][!] Logon Script Indicators[/yellow]")
        console.print(f"  [dim]Detection: Logon script path pattern matching[/dim]")
        for pattern in logon_findings["patterns"]:
            console.print(f"    [yellow]*[/yellow] {pattern} [dim](from persistence_detection.py)[/dim]")
            output_lines.append(f"  [!] Logon Script: {pattern} (from persistence_detection.py)")
        console.print("")
    
    # Final assessment
    if persistence_dict["methods_found"]:
        persistence_dict["is_persistent"] = True
        count = len(persistence_dict["methods_found"])
        methods_str = ", ".join(persistence_dict["methods_found"])
        console.print(f"[bold red]PERSISTENT MALWARE DETECTED ({count} method(s))[/bold red]")
        console.print(f"[dim]Methods: {methods_str}[/dim]\n")
        output_lines.append(f"\n[PERSISTENT] {count} persistence mechanism(s) found")
    else:
        console.print("[green][OK] No persistence mechanisms detected[/green]\n")
        output_lines.append("\n[OK] No persistence mechanisms found")
    
    return persistence_dict, output_lines


def _check_registry_persistence(strings: List[str]) -> Dict:
    """Check for registry Run key patterns."""
    findings = {
        "found": False,
        "patterns": []
    }
    
    run_key_patterns = PERSISTENCE_PATTERNS_CONFIG['registry_run_keys']
    
    for string in strings:
        for pattern in run_key_patterns:
            if re.search(pattern, string, re.IGNORECASE):
                findings["found"] = True
                findings["patterns"].append(string)
                break
    
    # Remove duplicates
    findings["patterns"] = list(set(findings["patterns"]))
    return findings


def _check_service_persistence(strings: List[str]) -> Dict:
    """Check for service installation APIs."""
    findings = {
        "found": False,
        "apis": []
    }
    
    # Pre-normalize service APIs to set for O(1) lookup
    service_apis_set = set(api.lower() for api in PERSISTENCE_PATTERNS_CONFIG['service_apis'])
    
    # Check imported APIs
    apis_found = set()
    for string in strings:
        string_lower = string.lower()
        if any(api in string_lower for api in service_apis_set):
            for api in service_apis_set:
                if api in string_lower:
                    apis_found.add(api)
    
    if apis_found:
        findings["found"] = True
        findings["apis"] = list(apis_found)
    
    return findings


def _check_scheduled_task_persistence(strings: List[str]) -> Dict:
    """Check for scheduled task indicators."""
    findings = {
        "found": False,
        "indicators": []
    }
    
    # Pre-normalize task indicators to set for O(1) lookup
    task_indicators_set = set(ind.lower() for ind in PERSISTENCE_PATTERNS_CONFIG['task_scheduler_indicators'])
    
    found_indicators = set()
    for string in strings:
        string_lower = string.lower()
        if any(indicator in string_lower for indicator in task_indicators_set):
            for indicator in task_indicators_set:
                if indicator in string_lower:
                    found_indicators.add(indicator)
    
    if found_indicators:
        findings["found"] = True
        findings["indicators"] = list(found_indicators)
    
    return findings


def _check_startup_persistence(strings: List[str]) -> Dict:
    """Check for startup folder references.
    IMPORTANT: Filters out false positives from CRT initialization and graphics APIs.
    """
    findings = {
        "found": False,
        "patterns": []
    }
    
    # False positive filters: These are normal C++ runtime and graphics initialization
    # NOT actual persistence mechanisms
    false_positive_patterns = {
        r"getstartupinfo",  # CRT initialization (not startup folder persistence)
        r"gdiplus",         # Graphics subsystem initialization
        r"gdiplusstartup",  # GDI+ initialization
        r"coinitialize",    # COM initialization
        r"oleinitialization",  # OLE initialization
    }
    
    startup_patterns = PERSISTENCE_PATTERNS_CONFIG['startup_folder_patterns']
    
    found_patterns = set()
    for string in strings:
        # Skip if this is a known false positive
        string_lower = string.lower()
        if any(re.search(fp_pattern, string_lower) for fp_pattern in false_positive_patterns):
            continue
            
        for pattern in startup_patterns:
            if re.search(pattern, string, re.IGNORECASE):
                found_patterns.add(string)
    
    if found_patterns:
        findings["found"] = True
        findings["patterns"] = list(found_patterns)
    
    return findings


def _check_wmi_persistence(strings: List[str]) -> Dict:
    """Check for WMI event subscription patterns."""
    findings = {
        "found": False,
        "indicators": []
    }
    
    wmi_indicators = PERSISTENCE_PATTERNS_CONFIG['wmi_indicators']
    
    found_indicators = set()
    for string in strings:
        for indicator in wmi_indicators:
            if indicator.lower() in string.lower():
                found_indicators.add(indicator)
    
    if found_indicators:
        findings["found"] = True
        findings["indicators"] = list(found_indicators)
    
    return findings


def _check_bho_persistence(strings: List[str]) -> Dict:
    """Check for Browser Helper Object patterns."""
    findings = {
        "found": False,
        "clsids": []
    }
    
    bho_patterns = PERSISTENCE_PATTERNS_CONFIG['bho_patterns']
    
    guid_pattern = r'\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}'
    
    found_clsids = set()
    for string in strings:
        # Look for GUIDs (CLSIDs)
        clsids = re.findall(guid_pattern, string)
        for clsid in clsids:
            found_clsids.add(clsid)
        
        # Look for BHO-specific strings
        for pattern in bho_patterns:
            if re.search(pattern, string, re.IGNORECASE):
                if "DllRegisterServer" in string or "CLSID" in string:
                    found_clsids.add(string)
    
    if found_clsids:
        findings["found"] = True
        findings["clsids"] = list(found_clsids)[:10]  # Limit to 10
    
    return findings


def _check_logon_persistence(strings: List[str]) -> Dict:
    """Check for logon script patterns."""
    findings = {
        "found": False,
        "patterns": []
    }
    
    logon_patterns = PERSISTENCE_PATTERNS_CONFIG['logon_script_patterns']
    
    found_patterns = set()
    for string in strings:
        for pattern in logon_patterns:
            if re.search(pattern, string, re.IGNORECASE):
                found_patterns.add(string)
    
    if found_patterns:
        findings["found"] = True
        findings["patterns"] = list(found_patterns)
    
    return findings
