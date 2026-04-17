"""
Executive summary generation module.

Creates high-level threat assessment summaries with key indicators,
complexity scores, and actionable recommendations.
"""

from typing import Tuple, Any, List, Dict
from src.utils.colors import C


def build_summary(
    yara_hits: int,
    packer_detected: Any,
    persistence_dict: Dict[str, Any],
    anti_analysis_dict: Dict[str, Any],
    shellcode_dict: Dict[str, Any],
    dll_hijacking_dict: Dict[str, Any],
    risk_level: str,
    threat_indicators: List[str]
) -> Tuple[Dict[str, bool], int, str, str, str, str]:
    """
    Build executive summary with key indicators and recommendations.
    
    Returns:
        Tuple containing:
        - indicators dict (is_packed, has_c2, has_persistence, has_anti_analysis)
        - complexity_score (0-6)
        - complexity level (BASIC, INTERMEDIATE, ADVANCED)
        - recommendation (markup-formatted)
        - rec_detail (detail text)
        - packer_names (formatted packer list)
    """
    # Determine key indicators
    is_packed = packer_detected.get("total_found", 0) > 0 if isinstance(packer_detected, dict) else len(packer_detected) > 0
    packer_names = packer_detected.get("packer_identified", []) if isinstance(packer_detected, dict) else []
    
    has_c2 = yara_hits > 0  # Simplified - could expand with behavior analysis
    has_persistence = persistence_dict.get("is_persistent", False)
    has_anti_analysis = bool(anti_analysis_dict.get("anti_debug_apis")) or bool(anti_analysis_dict.get("anti_vm_apis"))
    
    # Calculate complexity score
    complexity_score = sum([
        is_packed,
        has_c2,
        has_persistence,
        has_anti_analysis,
        shellcode_dict.get("total_found", 0) > 0,
        dll_hijacking_dict.get("has_hijacking_risk", False),
    ])
    
    # Determine complexity level
    if complexity_score >= 5:
        complexity = "ADVANCED"
    elif complexity_score >= 3:
        complexity = "INTERMEDIATE"
    else:
        complexity = "BASIC"
    
    # Build recommendation based on risk level
    if risk_level == "[bold red]CRITICAL[/bold red]":
        recommendation = "[bold red]SANDBOX ANALYSIS REQUIRED[/bold red]"
        rec_detail = "High-confidence malware indicators detected - immediate sandbox analysis recommended"
    elif risk_level == "[red]HIGH[/red]":
        recommendation = "[bold yellow]SANDBOX ANALYSIS RECOMMENDED[/bold yellow]"
        rec_detail = "Suspicious indicators present - sandbox testing advised"
    elif risk_level == "[yellow]MEDIUM[/yellow]":
        recommendation = "[yellow]MONITOR / INVESTIGATE[/yellow]"
        rec_detail = "Some suspicious patterns detected - further investigation recommended"
    else:
        recommendation = "[green]LIKELY BENIGN[/green]"
        rec_detail = "No significant malware indicators detected"
    
    indicators = {
        "is_packed": is_packed,
        "has_c2": has_c2,
        "has_persistence": has_persistence,
        "has_anti_analysis": has_anti_analysis,
    }
    
    return indicators, complexity_score, complexity, recommendation, rec_detail, packer_names


def format_summary_details(
    indicators: Dict[str, bool],
    yara_hits: int,
    packer_names: List[str],
    persistence_dict: Dict[str, Any],
    complexity_score: int,
    complexity: str
) -> Tuple[str, str, str, str, str]:
    """
    Format summary detail strings for display.
    
    Returns:
        Tuple of (packer_detail, c2_detail, persistence_detail, 
                  complexity_color_markup, complexity_color_end)
    """
    packer_detail = f"({', '.join(packer_names)})" if packer_names else "(various techniques)"
    c2_detail = f"({yara_hits} YARA matches)" if yara_hits else ""
    persistence_detail = f"({len(persistence_dict.get('methods_found', []))} method(s))" if indicators["has_persistence"] else ""
    
    complexity_color_markup = C.BOLD_RED if complexity_score >= 5 else C.BOLD_YELLOW if complexity_score >= 3 else C.GREEN
    complexity_color_end = C.END_BOLD_RED if complexity_score >= 5 else C.END_BOLD_YELLOW if complexity_score >= 3 else C.END_GREEN
    
    return packer_detail, c2_detail, persistence_detail, complexity_color_markup, complexity_color_end
