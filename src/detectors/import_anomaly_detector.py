# import_anomalies.py
"""
Import Anomalies Detection Module

Detects suspicious import patterns that indicate:
- Dynamic API loading (GetProcAddress usage)
- Unusual DLL imports
- Suspicious function imports
- Import table poisoning
- Delay loading abuse

Malware frequently uses dynamic loading to avoid static analysis
and to load C2/payload APIs at runtime.
"""

from config.import_anomaly_config import IMPORT_ANOMALIES_CONFIG, IMPORT_ANOMALY_SCORES
from typing import Dict, Any
import pefile


# Configuration imported from config.py - see IMPORT_ANOMALIES_CONFIG

def analyze_imports(pe: pefile.PE) -> Dict:
    """
    Analyze imported DLLs and functions for suspicious patterns.
    
    Args:
        pe: pefile.PE object
        
    Returns:
        Dict with:
            - suspicious_functions: List of suspicious imports
            - suspicious_dlls: List of suspicious DLLs
            - dynamic_loading_detected: Boolean
            - anomaly_score: 0-100
            - findings: List of specific findings
    """
    results = {
        "suspicious_functions": [],
        "suspicious_dlls": [],
        "dynamic_loading_detected": False,
        "anomaly_score": 0,
        "findings": []
    }
    
    if not hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        return results
    
    anomaly_score = 0
    function_count = {}
    dll_imports = {}
    
    # Get config maps
    suspicious_functions_map = IMPORT_ANOMALIES_CONFIG['suspicious_functions']
    suspicious_dlls_map = IMPORT_ANOMALIES_CONFIG['suspicious_dlls']
    
    # Collect all imported functions
    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        dll_name = entry.dll.decode("utf-8", errors="ignore").lower()
        dll_imports[dll_name] = []
        
        # Check if DLL itself is suspicious
        if dll_name in suspicious_dlls_map:
            results["suspicious_dlls"].append({
                "dll": dll_name,
                "severity": suspicious_dlls_map[dll_name]["severity"],
                "reason": suspicious_dlls_map[dll_name]["reason"]
            })
            anomaly_score += IMPORT_ANOMALY_SCORES["forward_reference"]
        
        for imp in entry.imports:
            func_name = imp.name.decode("utf-8", errors="ignore") if imp.name else "UNKNOWN"
            dll_imports[dll_name].append(func_name)
            
            # Check if function is suspicious
            if func_name in suspicious_functions_map:
                results["suspicious_functions"].append({
                    "function": func_name,
                    "dll": dll_name,
                    "severity": suspicious_functions_map[func_name]["severity"],
                    "reason": suspicious_functions_map[func_name]["reason"]
                })
                
                # Weight the severity
                if suspicious_functions_map[func_name]["severity"] == "CRITICAL":
                    anomaly_score += IMPORT_ANOMALY_SCORES["missing_dll"]
                elif suspicious_functions_map[func_name]["severity"] == "HIGH":
                    anomaly_score += IMPORT_ANOMALY_SCORES["invalid_export"]
                elif suspicious_functions_map[func_name]["severity"] == "MEDIUM":
                    anomaly_score += IMPORT_ANOMALY_SCORES["circular_dependency"]
                else:
                    anomaly_score += IMPORT_ANOMALY_SCORES["stub_export"]
    
    # Detect specific anomaly patterns
    
    # Pattern 1: GetProcAddress + LoadLibrary = Dynamic loading
    has_getproc = any(f["function"] == "GetProcAddress" for f in results["suspicious_functions"])
    has_loadlib = any(f["function"] == "LoadLibrary" for f in results["suspicious_functions"])
    
    if has_getproc and has_loadlib:
        results["dynamic_loading_detected"] = True
        results["findings"].append("PATTERN: Dynamic API loading detected (GetProcAddress + LoadLibrary)")
        anomaly_score += IMPORT_ANOMALY_SCORES["missing_function"]
    elif has_getproc:
        results["dynamic_loading_detected"] = True
        results["findings"].append("PATTERN: GetProcAddress detected - likely uses dynamic API loading")
        anomaly_score += IMPORT_ANOMALY_SCORES["circular_import"]
    
    # Pattern 2: Injection combo (CreateRemoteThread + WriteProcessMemory)
    has_createremote = any(f["function"] == "CreateRemoteThread" for f in results["suspicious_functions"])
    has_writeprocess = any(f["function"] == "WriteProcessMemory" for f in results["suspicious_functions"])
    
    if has_createremote and has_writeprocess:
        results["findings"].append("PATTERN: Process injection detected (CreateRemoteThread + WriteProcessMemory)")
        anomaly_score += IMPORT_ANOMALY_SCORES["multiple_missing"]
    
    # Pattern 3: Registry persistence (RegOpenKeyEx + RegSetValueEx)
    has_regopen = any(f["function"] == "RegOpenKeyEx" for f in results["suspicious_functions"])
    has_regset = any(f["function"] == "RegSetValueEx" for f in results["suspicious_functions"])
    
    if has_regopen and has_regset:
        results["findings"].append("PATTERN: Registry persistence likely (RegOpenKeyEx + RegSetValueEx)")
        anomaly_score += IMPORT_ANOMALY_SCORES["forwarded_circular"]
    
    # Normalize anomaly score
    results["anomaly_score"] = min(anomaly_score, 100)
    
    return results


def display_import_anomalies(pe: pefile.PE, console: Any):
    """
    Display import anomaly analysis in formatted output.
    
    Args:
        pe: pefile.PE object
        console: Rich Console for output
    """
    console.print("\n[bold cyan]Import Anomalies Analysis[/bold cyan]")
    console.print("[dim]Detecting suspicious imported functions and DLLs[/dim]\n")
    
    results = analyze_imports(pe)
    
    # Get thresholds from config
    critical_threshold = IMPORT_ANOMALIES_CONFIG['score_thresholds']['critical']
    warning_threshold = IMPORT_ANOMALIES_CONFIG['score_thresholds']['warning']
    
    if results["anomaly_score"] > critical_threshold:
        console.print(f"[bold red][!] CRITICAL: High import anomaly score ({results['anomaly_score']}/100)[/bold red] [dim](from import_anomalies.py)[/dim]\n")
    elif results["anomaly_score"] > warning_threshold:
        console.print(f"[yellow][!] WARNING: Moderate import anomalies detected ({results['anomaly_score']}/100)[/yellow] [dim](from import_anomalies.py)[/dim]\n")
    else:
        console.print(f"[green][OK] Import anomaly score: {results['anomaly_score']}/100 (from import_anomalies.py)[/green]\n")
    
    
    # Display suspicious functions (comprehensive view)
    if results["suspicious_functions"]:
        console.print(f"[bold yellow]Suspicious Functions ({len(results['suspicious_functions'])}):[/bold yellow] [dim](from import_anomalies.py)[/dim]")
        
        # Group by severity
        critical = [f for f in results["suspicious_functions"] if f["severity"] == "CRITICAL"]
        high = [f for f in results["suspicious_functions"] if f["severity"] == "HIGH"]
        medium = [f for f in results["suspicious_functions"] if f["severity"] == "MEDIUM"]
        
        if critical:
            console.print("[bold red]  CRITICAL:[/bold red]")
            for func in critical[:5]:  # Show top 5
                console.print(f"    * {func['function']} ({func['dll']}) - {func['reason']}")
        
        if high:
            console.print("[bold yellow]  HIGH:[/bold yellow]")
            for func in high[:5]:
                console.print(f"    * {func['function']} ({func['dll']}) - {func['reason']}")
        
        if medium and len(critical) + len(high) < 5:  # Only show if space
            console.print("[yellow]  MEDIUM:[/yellow]")
            for func in medium[:3]:
                console.print(f"    * {func['function']} ({func['dll']}) - {func['reason']}")
        console.print("")
        console.print("[dim]Note: Standard system DLLs (kernel32.dll, user32.dll, advapi32.dll) are expected in Windows binaries.[/dim]")
        console.print("[dim]Severity shown above reflects the imported function, not the DLL itself.\n[/dim]")
    
    # Display suspicious DLLs (now only truly unusual ones, not standard system DLLs)
    if results["suspicious_dlls"]:
        console.print(f"[bold yellow]Unusual/Suspicious DLLs ({len(results['suspicious_dlls'])}):[/bold yellow]")
        for dll in results["suspicious_dlls"]:
            console.print(f"  * {dll['dll']} - {dll['reason']}")
        console.print("")
    
    if results["dynamic_loading_detected"]:
        console.print("[bold magenta][!] Dynamic API loading detected - potential anti-analysis technique[/bold magenta]\n")
    
    return results
