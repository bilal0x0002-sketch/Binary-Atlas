"""
PE analysis orchestration and execution engine.

Handles the core analysis workflow: executing all analysis
modules sequentially, and coordinating results.
"""

import time
from typing import Dict, Any, List, Tuple

from src.parsing.headers import analyze_headers
from src.parsing.sections import analyze_sections
from src.parsing.security_checks import perform_security_checks

from src.detectors.threat_classifier import analyze_threats
from src.detectors.packer_detector import detect_advanced_packing
from src.detectors.yara_scanner import load_yara_rules, scan_with_yara, display_yara_results
from src.detectors.string_entropy import display_string_entropy_analysis
from src.detectors.import_anomaly_detector import display_import_anomalies
from src.detectors.resource_analyzer import display_resource_analysis
from src.detectors.overlay_detector import display_overlay_analysis
from src.detectors.persistence_detector import detect_persistence_mechanisms
from src.detectors.dll_hijacking_detector import detect_dll_hijacking
from src.detectors.anti_analysis_detector import detect_anti_analysis
from src.detectors.mutex_detector import detect_mutex_signatures
from src.detectors.com_hijacking_detector import detect_com_hijacking
from src.detectors.shellcode_detector import detect_shellcode
from src.detectors.compiler_detector import detect_compiler

from src.utils.entropy import calc_entropy
from src.utils.imports import analyze_imports
from src.utils.indicators import extract_indicators
from src.utils.colors import C
from src.utils.utils import is_windows_trusted_signature

from config.yara_scanner_config import YARA_RULES_PATH


# Global YARA rules cache
_YARA_RULES_CACHE = None

def get_yara_rules_cached():
    """Load YARA rules once and cache for batch processing."""
    global _YARA_RULES_CACHE
    if _YARA_RULES_CACHE is None:
        _YARA_RULES_CACHE = load_yara_rules(YARA_RULES_PATH)
    return _YARA_RULES_CACHE


def run_core_analysis(pe: Any, output_console: Any, formatter: Any, args: Any, indicators_dict: Dict[str, Any]) -> Dict[str, Any]:
    """
    Execute core analysis modules sequentially.
    
    Returns dict with module results keyed by module name.
    """
    analysis_modules = [
        ("Headers", lambda: analyze_headers(pe, output_console)),
        ("Sections", lambda: analyze_sections(pe, output_console, calc_entropy)),
        ("Imports", lambda: analyze_imports(pe, output_console)),
        ("Security Checks", lambda: perform_security_checks(pe, output_console)),
        ("Indicators", lambda: extract_indicators(pe, output_console)),
        ("Advanced Packing", lambda: detect_advanced_packing(pe, output_console)),
    ]
    
    analysis_results = {}
    all_imports = []  # Collect for compiler detection
    debug_info = {}   # Collect for compiler detection
    
    for module_name, module_func in analysis_modules:
        try:
            start_time = time.time()
            result = module_func()
            
            # Store result with appropriate key name
            if module_name == "Advanced Packing":
                analysis_results["packer_detection"] = result[0] if result else {}  # Store Dict, not Tuple
            else:
                analysis_results[module_name] = result
            
            elapsed = time.time() - start_time
            if args.verbose:
                formatter.print_module_timing(module_name, elapsed)
            
            # Update indicators_dict after Indicators analysis
            if module_name == "Indicators":
                indicators_dict.clear()
                indicators_dict.update(analysis_results["Indicators"][0] if analysis_results["Indicators"] else {})
            
            # Collect imports for compiler detection
            if module_name == "Imports" and result:
                # result is (found_suspicious, output_lines, dll_imports_dict)
                if len(result) > 2 and result[2]:
                    all_imports = list(result[2].keys())
            
            # Collect debug info from Security Checks (includes headers info)
            if module_name == "Security Checks" and result:
                debug_info = result if isinstance(result, dict) else {}
        except (SystemExit, KeyboardInterrupt):
            raise
        except Exception as e:
            import traceback
            error_msg = str(e)
            output_console.display_console.print(f"[yellow][!] {module_name} analysis failed: {error_msg}[/yellow]")
            if args.verbose:
                output_console.display_console.print(f"[dim]{traceback.format_exc()}[/dim]")
    
    # ==================== COMPILER DETECTION ====================
    try:
        start_time = time.time()
        compiler_result = detect_compiler(pe, all_imports, debug_info)
        analysis_results["Compiler"] = compiler_result
        
        # Print compiler info to console (use output_console.buffer_console to capture to text_buffer)
        output_console.buffer_console.print("\n[bold cyan]Compiler & Build Environment[/bold cyan]")
        
        if compiler_result.get("detected_compilers"):
            compilers = ", ".join(compiler_result["detected_compilers"])
            output_console.buffer_console.print(f"[blue]Detected Compiler:[/blue] {compilers}")
        else:
            output_console.buffer_console.print("[dim]No compiler-specific DLLs detected (may use static linking or non-standard toolchain)[/dim]")
        
        if compiler_result.get("compiler_version"):
            output_console.buffer_console.print(f"[blue]Version:[/blue] {compiler_result['compiler_version']}")
        
        if compiler_result.get("language_runtimes"):
            runtimes = ", ".join(compiler_result["language_runtimes"])
            output_console.buffer_console.print(f"[green]Language Runtime:[/green] {runtimes}")
        
        if compiler_result.get("build_info"):
            output_console.buffer_console.print("[yellow]Build Info:[/yellow]")
            for info in compiler_result["build_info"]:
                output_console.buffer_console.print(f"  - {info}")
        
        elapsed = time.time() - start_time
        if args.verbose:
            formatter.print_module_timing("Compiler Detection", elapsed)
    except Exception as e:
        import traceback
        error_msg = str(e)
        output_console.buffer_console.print(f"[yellow][!] Compiler detection failed: {error_msg}[/yellow]")
        if args.verbose:
            output_console.buffer_console.print(f"[dim]{traceback.format_exc()}[/dim]")
    
    return analysis_results


def run_advanced_analysis(pe: Any, path: str, output_console: Any, display_console: Any, args: Any, formatter: Any, 
                         threat_indicators: List[str], analysis_results: Dict[str, Any], 
                         indicators_dict: Dict[str, Any]) -> Tuple[int, int, List[Dict[str, Any]]]:
    """
    Execute advanced analysis modules: YARA, entropy, anomalies, resource, etc.
    
    Returns (yara_hits, yara_count, yara_matches)
    """
    
    # ==================== SIGNATURE VERIFICATION (CONFIDENCE FACTOR) ====================
    # Check signature to use as a confidence modifier, NOT to skip analysis
    # ⚠️ IMPORTANT: Signed malware exists (stolen certs, trojans, signed loaders)
    # Signature should BOOST trust, but NEVER skip heuristic analysis
    is_trusted = is_windows_trusted_signature(path)
    analysis_results["signature_verified"] = is_trusted
    
    if is_trusted:
        # Valid signature exists - this is a positive signal, but NOT conclusive
        # The threat_classifier will use this to reduce confidence on weak signals
        output_console.buffer_console.print("\n[green][✓] Binary has valid Windows signature[/green]")
        output_console.buffer_console.print("[dim]Note: Signature boosts trust but does not skip analysis (signed malware exists)[/dim]\n")
    else:
        output_console.buffer_console.print("\n[yellow][!] Binary is unsigned or has invalid signature[/yellow]\n")
    
    # Continue with FULL heuristic analysis regardless of signature status
    yara_hits = 0
    yara_matches = []
    
    # ==================== YARA SCANNING ====================
    try:
        start_time = time.time()
        yara_rules = get_yara_rules_cached()
        yara_matches, yara_hits = scan_with_yara(path, yara_rules)
        # Store YARA results in analysis_results for threat_classifier
        analysis_results["yara_matches"] = yara_matches
        # YARA results are now merged into unified threat classification (threat_classifier.py)
        # display_yara_results() call removed to avoid duplication
        elapsed = time.time() - start_time
        if args.verbose:
            formatter.print_module_timing("YARA Scan", elapsed)
        
        if yara_hits > 0:
            for severity in ["critical", "high"]:
                threat_count = sum(1 for m in yara_matches if m.get("severity") == severity)
                if threat_count > 0:
                    threat_level = "CRITICAL" if severity == "critical" else "HIGH"
                    threat_indicators.extend([threat_level] * threat_count)
    except Exception as e:
        error_msg = str(e).replace("[", "(").replace("]", ")")
        display_console.print(f"[yellow][!] YARA scanning failed: {error_msg}[/yellow]")
    
    # ==================== TIER 1 ADVANCED ANALYSIS ====================
    try:
        start_time = time.time()
        strings_for_entropy = indicators_dict.get("strings", []) if indicators_dict else []
        string_entropy_results = display_string_entropy_analysis(pe, output_console, strings_for_entropy)
        analysis_results["string_entropy"] = string_entropy_results
        elapsed = time.time() - start_time
        if args.verbose:
            formatter.print_module_timing("String Entropy", elapsed)
    except Exception as e:
        display_console.print(f"[yellow][!] String entropy analysis failed: {e}[/yellow]")
    
    try:
        start_time = time.time()
        import_anomaly_results = display_import_anomalies(pe, output_console)
        analysis_results["import_anomalies"] = import_anomaly_results
        if import_anomaly_results.get("anomaly_score", 0) > 30:
            threat_indicators.append("HIGH")
        elapsed = time.time() - start_time
        if args.verbose:
            formatter.print_module_timing("Import Anomalies", elapsed)
    except Exception as e:
        display_console.print(f"[yellow][!] Import anomaly analysis failed: {e}[/yellow]")
    
    try:
        start_time = time.time()
        dll_hijacking_results, dll_hijacking_lines = detect_dll_hijacking(pe, output_console, verbose=args.verbose)
        analysis_results["dll_hijacking"] = dll_hijacking_results
        if dll_hijacking_results.get("has_hijacking_risk", False):
            threat_indicators.append("HIGH")
        elapsed = time.time() - start_time
        if args.verbose:
            formatter.print_module_timing("DLL Hijacking Detection", elapsed)
    except Exception as e:
        display_console.print(f"[yellow][!] DLL hijacking analysis failed: {e}[/yellow]")
    
    try:
        start_time = time.time()
        resource_analysis_results = display_resource_analysis(pe, output_console)
        analysis_results["resource_analysis"] = resource_analysis_results
        if resource_analysis_results.get("embedded_pe_count", 0) > 0:
            threat_indicators.append("CRITICAL")
        elapsed = time.time() - start_time
        if args.verbose:
            formatter.print_module_timing("Resource Analysis", elapsed)
    except Exception as e:
        display_console.print(f"[yellow][!] Resource analysis failed: {e}[/yellow]")
    
    try:
        start_time = time.time()
        shellcode_results, shellcode_lines = detect_shellcode(pe, output_console)
        analysis_results["shellcode_detection"] = shellcode_results
        if shellcode_results.get("total_found", 0) > 0:
            if shellcode_results.get("sophistication") == "ADVANCED":
                threat_indicators.append("CRITICAL")
            elif shellcode_results.get("sophistication") in ["INTERMEDIATE", "BASIC"]:
                threat_indicators.append("HIGH")
        elapsed = time.time() - start_time
        if args.verbose:
            formatter.print_module_timing("Shellcode Detection", elapsed)
    except Exception as e:
        display_console.print(f"[yellow][!] Shellcode detection analysis failed: {e}[/yellow]")
    
    try:
        start_time = time.time()
        overlay_results = display_overlay_analysis(path, pe, output_console)
        analysis_results["overlay_analysis"] = overlay_results
        if overlay_results.get("contains_pe", False):
            threat_indicators.append("CRITICAL")
        elif overlay_results.get("has_overlay", False) and overlay_results.get("overlay_entropy", 0) > 7.0:
            threat_indicators.append("HIGH")
        elapsed = time.time() - start_time
        if args.verbose:
            formatter.print_module_timing("Overlay Analysis", elapsed)
    except Exception as e:
        error_msg = str(e).replace("[", "(").replace("]", ")")
        display_console.print(f"[yellow][!] Overlay analysis failed: {error_msg}[/yellow]")
    
    try:
        start_time = time.time()
        anti_analysis_results, anti_analysis_lines = detect_anti_analysis(pe, output_console)
        analysis_results["anti_analysis"] = anti_analysis_results
        if anti_analysis_results.get("severity") == "HIGH":
            threat_indicators.append("HIGH")
        elif anti_analysis_results.get("severity") == "CRITICAL":
            threat_indicators.append("CRITICAL")
        elapsed = time.time() - start_time
        if args.verbose:
            formatter.print_module_timing("Anti-Analysis Detection", elapsed)
    except Exception as e:
        display_console.print(f"[yellow][!] Anti-analysis detection failed: {e}[/yellow]")
    
    try:
        start_time = time.time()
        persistence_results, persistence_lines = detect_persistence_mechanisms(pe, output_console)
        analysis_results["persistence_detection"] = persistence_results
        if persistence_results.get("is_persistent", False):
            threat_indicators.append("HIGH")
        elapsed = time.time() - start_time
        if args.verbose:
            formatter.print_module_timing("Persistence Detection", elapsed)
    except Exception as e:
        display_console.print(f"[yellow][!] Persistence detection analysis failed: {e}[/yellow]")
    
    try:
        start_time = time.time()
        com_hijacking_results, com_hijacking_lines = detect_com_hijacking(pe, output_console)
        analysis_results["com_hijacking"] = com_hijacking_results
        if com_hijacking_results.get("is_highrisk", False):
            threat_indicators.append("HIGH")
        elif com_hijacking_results.get("total_found", 0) > 0:
            threat_indicators.append("MEDIUM")
        elapsed = time.time() - start_time
        if args.verbose:
            formatter.print_module_timing("COM Hijacking Detection", elapsed)
    except Exception as e:
        display_console.print(f"[yellow][!] COM hijacking detection failed: {e}[/yellow]")
    
    try:
        start_time = time.time()
        mutex_results, mutex_lines = detect_mutex_signatures(pe, output_console)
        analysis_results["mutex_signatures"] = mutex_results
        if mutex_results.get("severity") == "CRITICAL":
            threat_indicators.append("CRITICAL")
        elif mutex_results.get("severity") == "HIGH":
            threat_indicators.append("HIGH")
        elif mutex_results.get("severity") == "MEDIUM":
            threat_indicators.append("MEDIUM")
        elapsed = time.time() - start_time
        if args.verbose:
            formatter.print_module_timing("Mutex Signatures", elapsed)
    except Exception as e:
        display_console.print(f"[yellow][!] Mutex signature analysis failed: {e}[/yellow]")
    
    try:
        start_time = time.time()
        # Add file path for context awareness (signature/system binary checking)
        analysis_results["file_path"] = path
        # Unified threat classification combines behavior + patterns + YARA
        threat_report = analyze_threats(pe, output_console, analysis_results)
        if threat_report.get("threat_level") == "CRITICAL":
            threat_indicators.append("CRITICAL")
        elif threat_report.get("threat_level") == "HIGH":
            threat_indicators.append("HIGH")
        elapsed = time.time() - start_time
        if args.verbose:
            formatter.print_module_timing("Unified Threat Classification", elapsed)
    except Exception as e:
        display_console.print(f"[yellow][!] Unified threat classification failed: {e}[/yellow]")
    
    return yara_hits, len(yara_matches), yara_matches
