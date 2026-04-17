"""
YARA Scanner Module

Handles YARA rule compilation and malware signature matching.
Supports multiple rule files organized by detection category.
"""

import yara
import os
from typing import Dict, List, Tuple
from ..utils.logger import get_logger
from config.yara_scanner_config import YARA_SCANNER_CONFIG

logger = get_logger()


def load_yara_rules(rule_directory: str) -> Dict[str, any]:
    """
    Load and compile all YARA rules from directory.
    
    Args:
        rule_directory: Path to directory containing .yar/.yara files
        
    Returns:
        Dict mapping filename -> compiled rule object (or error string)
    """
    rules = {}
    
    if not os.path.exists(rule_directory):
        logger.warning(f"Rule directory not found: {rule_directory}")
        return {}
    
    for filename in os.listdir(rule_directory):
        # Check if file matches configured rule extensions
        rule_extensions = YARA_SCANNER_CONFIG['rule_extensions']
        if any(filename.endswith(ext) for ext in rule_extensions):
            filepath = os.path.join(rule_directory, filename)
            try:
                rules[filename] = yara.compile(filepath=filepath)
                logger.debug(f"Loaded YARA rules from {filename}")
            except yara.Error as e:
                logger.warning(f"YARA compilation failed for {filename}: {str(e)}")
                # Skip this rule file and continue with others
            except Exception as e:
                logger.error(f"Error loading {filename}: {str(e)}", exc_info=False)
                # Continue with next rule file
    
    return rules


def scan_with_yara(pe_path: str, rules: Dict) -> Tuple[List[Dict], int]:
    """
    Scan PE file against all YARA rules.
    
    Args:
        pe_path: Path to PE file to scan
        rules: Dict of compiled YARA rules
        
    Returns:
        Tuple of (matches list, total hits)
        Match format: {'rule': name, 'file': source, 'severity': level, 'family': family_name}
    """
    matches = []
    total_hits = 0
    failed_rules = []
    
    if not rules:
        logger.debug("No YARA rules loaded")
        return matches, total_hits
    
    for rule_file, rule_obj in rules.items():
        # Skip error entries from load_yara_rules
        if not hasattr(rule_obj, 'match'):
            failed_rules.append(rule_file)
            continue
        
        try:
            scan_results = rule_obj.match(pe_path)
            
            for result in scan_results:
                # Each result is a Match object with rule name and metadata
                rule_name = result.rule
                rule_meta = result.meta if hasattr(result, 'meta') else {}
                
                # Extract metadata for better classification
                default_severity = YARA_SCANNER_CONFIG['default_severity']
                default_category = YARA_SCANNER_CONFIG['default_category']
                severity = rule_meta.get("severity", default_severity).lower() if rule_meta else default_severity
                category = rule_meta.get("category", default_category).lower() if rule_meta else default_category
                family = rule_meta.get("family", "").lower() if rule_meta else ""
                description = rule_meta.get("description", rule_name) if rule_meta else rule_name
                
                match_info = {
                    "rule": rule_name,
                    "file": rule_file,
                    "severity": severity,
                    "category": category,
                    "family": family,
                    "description": description
                }
                
                matches.append(match_info)
                total_hits += 1
                
        except Exception as e:
            # Track rule scan failures for debugging
            failed_rules.append(rule_file)
            logger.warning(f"YARA scan failed for {rule_file}: {str(e)}")
    
    # Log summary if there were failures
    if failed_rules:
        logger.warning(f"YARA scanning: {len(failed_rules)} rule(s) failed to scan: {', '.join(failed_rules)}")
    
    return matches, total_hits


def display_yara_results(matches: List[Dict], console):
    """
    Display YARA scan results in formatted output.
    
    Args:
        matches: List of match dicts from scan_with_yara
        console: Rich Console for output
    """
    if not matches:
        console.print("\n[bold cyan]YARA Signature Scanning[/bold cyan]")
        console.print("[dim]Matching against malware signatures[/dim]\n")
        console.print("[green][OK] No malware signatures matched[/green]\n")
        return
    
    console.print("\n[bold cyan]YARA Signature Scanning[/bold cyan]")
    console.print("[dim]Matching against malware signatures[/dim]\n")
    
    # Organize by severity using config severity levels
    critical_level = YARA_SCANNER_CONFIG['severity_levels']['critical'].lower()
    high_level = YARA_SCANNER_CONFIG['severity_levels']['high'].lower()
    medium_level = YARA_SCANNER_CONFIG['severity_levels']['medium'].lower()
    
    critical = [m for m in matches if m["severity"] == critical_level]
    high = [m for m in matches if m["severity"] == high_level]
    medium = [m for m in matches if m["severity"] == medium_level]
    
    if critical:
        console.print(f"[bold red][!] CRITICAL: {len(critical)} signature(s) matched![/bold red]")
        for match in critical:
            family = f" ({match['family']})" if match['family'] else ""
            console.print(f"    [red]*[/red] {match['rule']}{family}")
            console.print(f"       {match['description']}")
            console.print(f"       [dim]Source: {match['file']} | Detection: Signature rule match[/dim]")
        console.print("")
    
    if high:
        console.print(f"[bold yellow][!] HIGH SEVERITY: {len(high)} signature(s)[/bold yellow]")
        display_limit = YARA_SCANNER_CONFIG['high_severity_display_limit']
        for match in high[:display_limit]:  # Show top N
            family = f" ({match['family']})" if match['family'] else ""
            console.print(f"    [yellow]*[/yellow] {match['rule']}{family}")
            console.print(f"       {match['description']}")
            console.print(f"       [dim]Source: {match['file']}[/dim]")
        if len(high) > 5:
            console.print(f"    ... and {len(high) - 5} more (see full report)")
        console.print("")
    
    if medium:
        console.print(f"[blue][i] Medium: {len(medium)} signature(s)[/blue]")
        console.print(f"       [dim]Detection: Pattern matching against malware signatures[/dim]")
    
    console.print(f"[dim]Total YARA matches: {len(matches)} | Detection method: Binary signature scanning[/dim]\n")
