# string_entropy.py
"""
String Entropy Analysis Module

Analyzes individual extracted strings for encryption/obfuscation indicators.

High-entropy strings (7.0+) often indicate:
- Encrypted C2 commands
- Obfuscated configuration strings
- XOR-encoded data
- Base64-encoded payloads (before decode)
- Random-looking keys/tokens

Malware analysts look for this because encrypted strings frequently
contain sensitive C2 infrastructure or payload data.
"""

import math
import pefile
from collections import Counter
from typing import List, Dict, Any
from src.utils.entropy import calc_entropy
from config.string_entropy_config import STRING_ENTROPY_CONFIG, STRING_ENTROPY_DISPLAY_CONFIG

def calculate_string_entropy(string: str) -> float:
    """
    Calculate Shannon entropy of a string.
    
    Args:
        string: String to analyze
        
    Returns:
        float: Entropy value 0.0-8.0
        
    Interpretation:
        < 3.0: Normal readable text
        3.0-5.0: Mostly readable (some obfuscation)
        5.0-7.0: Likely encoded/compressed
        7.0+: Highly likely encrypted/obfuscated
    """
    if not string or len(string) < STRING_ENTROPY_DISPLAY_CONFIG['min_string_length_check']:
        return 0.0
    
    # Convert string to bytes and use the universal entropy function
    try:
        string_bytes = string.encode('utf-8')
        return calc_entropy(string_bytes)
    except (UnicodeEncodeError, AttributeError, TypeError):
        # Fallback to direct calculation
        entropy = 0.0
        counts = Counter(string)
        length = len(string)
        
        for count in counts.values():
            probability = count / length
            entropy -= probability * math.log2(probability)
        
        return entropy


def analyze_string_entropy(strings_list: List[str], threshold: float = None) -> Dict:
    """
    Analyze entropy of extracted strings and classify by suspiciousness.
    
    Args:
        strings_list: List of extracted strings to analyze
        threshold: Entropy threshold for flagging as suspicious (optional, uses config if not provided)
    
    Returns:
        Dict with:
            - high_entropy_strings: List of (string, entropy) tuples with high entropy
            - encrypted_indicators: List of suspected encrypted strings
            - summary: Statistics
    
    This helps identify:
        - Encrypted C2 commands
        - Obfuscated configuration
        - XOR-encoded payloads
    """
    if threshold is None:
        threshold = STRING_ENTROPY_CONFIG['main_threshold']
    
    high_entropy = []
    encrypted_indicators = []
    min_length = STRING_ENTROPY_CONFIG['min_string_length']
    critical_threshold = STRING_ENTROPY_CONFIG['critical_entropy_threshold']
    high_threshold = STRING_ENTROPY_CONFIG['high_entropy_threshold']
    
    for string in strings_list:
        if len(string) < min_length:  # Skip very short strings
            continue
            
        entropy = calculate_string_entropy(string)
        
        if entropy >= threshold:
            high_entropy.append((string, entropy))
            
            # Classify as encryption type
            if entropy >= critical_threshold:
                encrypted_indicators.append({
                    "string": string,
                    "entropy": entropy,
                    "confidence": "CRITICAL",
                    "suspected_type": "Heavily encrypted/compressed"
                })
            elif entropy >= high_threshold:
                encrypted_indicators.append({
                    "string": string,
                    "entropy": entropy,
                    "confidence": "HIGH",
                    "suspected_type": "Likely encoded"
                })
    
    return {
        "high_entropy_strings": high_entropy,
        "encrypted_indicators": encrypted_indicators,
        "total_analyzed": len(strings_list),
        "high_entropy_count": len(high_entropy),
        "critical_encrypted": len([x for x in encrypted_indicators if x["confidence"] == "CRITICAL"])
    }


def display_string_entropy_analysis(pe: pefile.PE, console: Any, strings_list: List[str]) -> None:
    """
    Display string entropy analysis in formatted output.
    
    Args:
        pe: pefile.PE object
        console: Rich Console for output
        strings_list: List of extracted strings
    """
    console.print("\n[bold cyan]String Entropy Analysis[/bold cyan]")
    console.print("[dim]Analyzing extracted strings for encryption/obfuscation indicators[/dim]\n")
    
    results = analyze_string_entropy(strings_list)
    
    if results["critical_encrypted"] > 0:
        console.print(f"[bold red][!] CRITICAL: {results['critical_encrypted']} highly encrypted strings detected[/bold red] [dim](from string_entropy.py)[/dim]")
        console.print("[dim]These may contain:")
        console.print("  - Encrypted C2 commands")
        console.print("  - Obfuscated configuration")
        console.print("  - XOR-encoded payloads[/dim]\n")
        
        # Show top N most encrypted
        display_limit = STRING_ENTROPY_DISPLAY_CONFIG['top_encrypted_display_limit']
        truncate_length = STRING_ENTROPY_DISPLAY_CONFIG['encrypted_string_truncate_length']
        sorted_encrypted = sorted(results["encrypted_indicators"], 
                                 key=lambda x: x["entropy"], 
                                 reverse=True)[:display_limit]
        for item in sorted_encrypted:
            console.print(f"  [red]{item['confidence']}[/red] (entropy: {item['entropy']:.2f}) - {item['string'][:truncate_length]}")
    
    elif results["high_entropy_count"] > 0:
        console.print(f"[yellow][i] {results['high_entropy_count']} high-entropy strings detected[/yellow] [dim](from string_entropy.py)[/dim]")
        console.print("[dim]Possible obfuscation or encoding[/dim]\n")
    else:
        console.print("[green][OK] No suspicious high-entropy strings found (from string_entropy.py)[/green]")
    
    console.print(f"[dim]Analyzed {results['total_analyzed']} strings total (from string_entropy.py)[/dim]\n")
    
    return results
