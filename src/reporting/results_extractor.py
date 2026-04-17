"""
Analysis module result extraction and unpacking.

Safely extracts and unpacks results from analysis modules with
type checking and default fallbacks.
"""

from typing import Dict, Any, Tuple, List


def extract_module_results(analysis_results: Dict[str, Any]) -> Tuple[Dict[str, Any], ...]:
    """
    Extract and unpack results from analysis modules with safe defaults.
    
    Args:
        analysis_results: Dict of all module results from sequential analysis
    
    Returns:
        Tuple of extracted results in order:
        (threat_indicators, found_suspicious_api, file_size, indicators_dict,
         packer_detected, dll_imports_data)
    """
    threat_indicators = []
    found_suspicious_api = False
    file_size = 0
    packer_detected = []
    indicators_dict = {}
    dll_imports_data = {}
    
    if "Sections" in analysis_results:
        # Sections returned but risk no longer used
        pass
    
    if "Imports" in analysis_results:
        try:
            found_suspicious_api, _, dll_imports_data = analysis_results["Imports"]
        except (ValueError, TypeError):
            # Graceful fallback if unpacking fails
            pass
    
    if "Security Checks" in analysis_results:
        try:
            file_size, _, _ = analysis_results["Security Checks"]
        except (ValueError, TypeError):
            pass
    
    if "Indicators" in analysis_results:
        try:
            indicators_dict, _ = analysis_results["Indicators"]
        except (ValueError, TypeError):
            pass
    
    if "Advanced Packing" in analysis_results:
        try:
            packer_detected, _ = analysis_results["Advanced Packing"]
        except (ValueError, TypeError):
            pass
    
    return threat_indicators, found_suspicious_api, file_size, indicators_dict, packer_detected, dll_imports_data


def extract_advanced_results(analysis_results: Dict[str, Any]) -> Tuple[Dict[str, Any], ...]:
    """
    Extract results from advanced analysis modules with safe unpacking.
    
    Args:
        analysis_results: Dict of all module results
    
    Returns:
        Tuple of (anti_analysis_dict, shellcode_dict, persistence_dict, 
                  dll_hijacking_dict, com_hijacking_dict)
    """
    anti_analysis_dict = {}
    shellcode_dict = {}
    persistence_dict = {}
    dll_hijacking_dict = {}
    com_hijacking_dict = {}
    
    # Anti-analysis
    if "anti_analysis" in analysis_results:
        result = analysis_results["anti_analysis"]
        if result and isinstance(result, dict):
            anti_analysis_dict = result
        elif result and isinstance(result, tuple):
            anti_analysis_dict = result[0] if result[0] else {}
    
    # Shellcode
    if "shellcode_detection" in analysis_results:
        result = analysis_results["shellcode_detection"]
        if result and isinstance(result, dict):
            shellcode_dict = result
        elif result and isinstance(result, tuple):
            shellcode_dict = result[0] if result[0] else {}
    
    # Persistence
    if "persistence_detection" in analysis_results:
        result = analysis_results["persistence_detection"]
        if result and isinstance(result, dict):
            persistence_dict = result
        elif result and isinstance(result, tuple):
            persistence_dict = result[0] if result[0] else {}
    
    # DLL Hijacking
    if "dll_hijacking" in analysis_results:
        result = analysis_results["dll_hijacking"]
        if result and isinstance(result, dict):
            dll_hijacking_dict = result
        elif result and isinstance(result, tuple):
            dll_hijacking_dict = result[0] if result[0] else {}
    
    # COM Hijacking
    if "com_hijacking" in analysis_results:
        result = analysis_results["com_hijacking"]
        if result and isinstance(result, dict):
            com_hijacking_dict = result
        elif result and isinstance(result, tuple):
            com_hijacking_dict = result[0] if result[0] else {}
    
    return anti_analysis_dict, shellcode_dict, persistence_dict, dll_hijacking_dict, com_hijacking_dict
