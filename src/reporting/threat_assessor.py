"""
Threat level assessment based on multiple indicators.
"""

from typing import List, Any, Tuple


def assess_threat_level(
    threat_indicators: List[str],
    yara_hits: int,
    found_suspicious_api: bool,
    packer_detected: Any,
    import_anomaly_score: int,
    entropy_count: int
) -> Tuple[str, str]:
    """
    Determine overall threat level from all indicators.
    
    Returns (risk_level_markup, risk_description)
    """
    critical_count = threat_indicators.count("CRITICAL")
    high_count = threat_indicators.count("HIGH")
    
    if critical_count > 0 or yara_hits > 0:
        return "[bold red]CRITICAL[/bold red]", "Strong indicators of malware or malicious behavior"
    elif high_count >= 3 or (high_count > 0 and (found_suspicious_api or packer_detected)):
        return "[red]HIGH[/red]", "Significant suspicious indicators detected"
    elif high_count > 0:
        return "[yellow]MEDIUM[/yellow]", "Some suspicious indicators present"
    elif import_anomaly_score > 30 or entropy_count > 0:
        return "[yellow]LOW[/yellow]", "Minor suspicious indicators"
    else:
        return "[green]MINIMAL[/green]", "No significant malware indicators detected"
