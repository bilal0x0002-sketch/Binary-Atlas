# resource_analysis.py
"""
Resource Section Analysis Module

Analyzes the .rsrc section for:
- Embedded PE files (droppers/staged malware)
- Suspicious resource types
- Resource entropy (encrypted/obfuscated resources)
- Unusual resource sizes
- PE magic bytes in resources

Malware often embeds payloads in resources to evade file analysis
or to stage multi-stage attacks.
"""

from config.resource_analysis_config import RESOURCE_ANALYSIS_CONFIG
from typing import List, Dict, Any
import struct
import math
import pefile
from collections import Counter

# PE magic bytes
PE_SIGNATURE = b"MZ"
PE_SIGNATURE_32 = b"PE\x00\x00"


def find_embedded_pes(resource_data: bytes) -> List[Dict]:
    """
    Search for PE file signatures in resource data.
    
    Args:
        resource_data: Raw bytes of resource data
        
    Returns:
        List of dicts with found PE locations and details
    """
    embedded_pes = []
    
    # Search for PE header signatures (MZ)
    offset = 0
    while True:
        offset = resource_data.find(PE_SIGNATURE, offset)
        if offset == -1:
            break
        
        # Check if this looks like a valid PE (has e_lfanew and PE signature at offset)
        try:
            if offset + RESOURCE_ANALYSIS_CONFIG['pe_header_min_buffer'] < len(resource_data):
                # Read e_lfanew (offset to PE signature) - at bytes 0x3C-0x3F
                e_lfanew = struct.unpack("<I", resource_data[offset + RESOURCE_ANALYSIS_CONFIG['pe_lfanew_offset']:offset + RESOURCE_ANALYSIS_CONFIG['pe_lfanew_offset'] + RESOURCE_ANALYSIS_CONFIG['pe_lfanew_size']])[0]
                
                # Sanity check: e_lfanew should be < max threshold
                if e_lfanew < RESOURCE_ANALYSIS_CONFIG['pe_e_lfanew_max'] and offset + e_lfanew + RESOURCE_ANALYSIS_CONFIG['pe_signature_size'] < len(resource_data):
                    # Check for PE signature at calculated offset
                    pe_sig = resource_data[offset + e_lfanew:offset + e_lfanew + RESOURCE_ANALYSIS_CONFIG['pe_signature_size']]
                    if pe_sig == PE_SIGNATURE_32:
                        embedded_pes.append({
                            "offset": offset,
                            "e_lfanew": e_lfanew,
                            "confidence": "HIGH"
                        })
        except (KeyError, AttributeError, TypeError) as e:
            pass
        except Exception as e:
            pass
        
        offset += 1
    
    return embedded_pes


def calculate_resource_entropy(data: bytes) -> float:
    """
    Calculate entropy of resource data.
    High entropy indicates encryption/compression.
    
    Args:
        data: Resource data bytes
        
    Returns:
        float: Entropy value 0.0-8.0
    """
    if not data or len(data) < 2:
        return 0.0
    
    entropy = 0.0
    counts = Counter(data)
    length = len(data)
    
    for count in counts.values():
        probability = count / length
        entropy -= probability * math.log2(probability)
    
    return entropy


def compute_resource_severity(results: Dict) -> str:
    """
    Compute overall severity of resource analysis findings.
    
    Args:
        results: Analysis results dict from analyze_resources()
        
    Returns:
        str: "CRITICAL", "HIGH", "MEDIUM", or "LOW"
    """
    # Embedded PE = instant CRITICAL
    if results.get("embedded_pe_count", 0) > 0:
        return "CRITICAL"
    
    # Suspicious resources = HIGH
    if len(results.get("suspicious_resources", [])) > 0:
        return "HIGH"
    
    # Multiple high-entropy resources = MEDIUM
    if len(results.get("high_entropy_resources", [])) > 3:
        return "MEDIUM"
    
    # Default to LOW
    return "LOW"


def analyze_resources(pe: pefile.PE) -> Dict:
    """
    Analyze PE resource section for suspicious content.
    
    Args:
        pe: pefile.PE object
        
    Returns:
        Dict with analysis results:
            - has_resources: Boolean
            - embedded_pe_count: Number of embedded PE files
            - suspicious_resources: List of suspicious findings
            - high_entropy_resources: List of encrypted/compressed resources
            - risk_score: 0-100
    """
    results = {
        "has_resources": False,
        "embedded_pe_count": 0,
        "suspicious_resources": [],
        "high_entropy_resources": [],
        "total_resources": 0,
        "severity": "LOW"
    }
    
    # Check if resource section exists
    if not hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
        return results
    
    results["has_resources"] = True
    
    # Safe file reading fallback
    try:
        if hasattr(pe, "__data__") and pe.__data__:
            file_data = pe.__data__
        else:
            # Safe fallback: read from file if PE object doesn't have __data__
            with open(pe.filename, "rb") as f:
                file_data = f.read()
    except Exception as e:
        # Can't read file data, return empty results
        return results
    
    try:
        def traverse_resources(directory, depth=0):
            # Depth limit to prevent malformed PE recursion attacks
            if depth > 10:
                return
            
            for entry in directory.entries:
                # Count total resources
                results["total_resources"] += 1
                
                # Get resource data if leaf node
                if hasattr(entry, "directory"):
                    traverse_resources(entry.directory, depth + 1)
                else:
                    # This is a data entry
                    try:
                        resource_offset = entry.data.struct.OffsetToData
                        resource_size = entry.data.struct.Size
                        
                        # Read resource data
                        if resource_offset < len(file_data) and resource_size > 0:
                            end_offset = min(resource_offset + resource_size, len(file_data))
                            resource_data = file_data[resource_offset:end_offset]
                            
                            # Check for embedded PE files
                            embedded_pes = find_embedded_pes(resource_data)
                            if embedded_pes:
                                results["embedded_pe_count"] += len(embedded_pes)
                                results["suspicious_resources"].append({
                                    "type": "Embedded PE file",
                                    "size": resource_size,
                                    "count": len(embedded_pes),
                                    "severity": "CRITICAL",
                                    "reason": "Possible dropper or staged malware"
                                })
                            
                            # Check resource entropy
                            if resource_size > RESOURCE_ANALYSIS_CONFIG['pe_resource_min_size']:  # Only check larger resources
                                entropy = calculate_resource_entropy(resource_data)
                                if entropy > RESOURCE_ANALYSIS_CONFIG['pe_entropy_threshold']:
                                    results["high_entropy_resources"].append({
                                        "size": resource_size,
                                        "entropy": entropy,
                                        "reason": "Likely encrypted or compressed"
                                    })
                            
                            # Check for uncommon or binary resource types
                            if hasattr(entry, "id"):
                                if entry.id > RESOURCE_ANALYSIS_CONFIG['resource_type_id_threshold']:  # Non-standard resource type
                                    if resource_size > RESOURCE_ANALYSIS_CONFIG['resource_size_threshold']:  # Unusually large
                                        results["suspicious_resources"].append({
                                            "type": f"Non-standard resource (ID: {entry.id})",
                                            "size": resource_size,
                                            "severity": "MEDIUM",
                                            "reason": "Unusual resource type and size"
                                        })
                    except (KeyError, AttributeError, TypeError, IndexError) as e:
                        # Skip malformed resource entries
                        pass
                    except Exception as e:
                        pass
        
        traverse_resources(pe.DIRECTORY_ENTRY_RESOURCE)
    except (AttributeError, TypeError) as e:
        # PE has no resources or malformed resource table
        pass
    except Exception as e:
        pass
    
    # Compute severity based on findings
    results["severity"] = compute_resource_severity(results)
    
    return results


def display_resource_analysis(pe: pefile.PE, console: Any) -> Dict:
    """
    Display resource analysis in formatted output.
    
    Args:
        pe: pefile.PE object
        console: Rich Console for output
    """
    console.print("\n[bold cyan]Resource Section Analysis[/bold cyan]")
    console.print("[dim]Analyzing .rsrc section for embedded files and anomalies[/dim]\n")
    
    results = analyze_resources(pe)
    
    if not results["has_resources"]:
        console.print("[yellow][i] No resource section found[/yellow]\n")
        return results
    
    console.print(f"[dim]Total resources: {results['total_resources']}[/dim]\n")
    
    # Embedded PE detection
    if results["embedded_pe_count"] > 0:
        console.print(f"[bold red][!] CRITICAL: {results['embedded_pe_count']} embedded PE files detected![/bold red] [dim](from resource_analysis.py)[/dim]")
        console.print("[dim]This may indicate:")
        console.print("  - Dropper malware")
        console.print("  - Staged attack payload")
        console.print("  - Multi-stage malware[/dim]\n")
    
    # Suspicious resources
    if results["suspicious_resources"]:
        console.print(f"[bold yellow]Suspicious Resources ({len(results['suspicious_resources'])}):[/bold yellow] [dim](from resource_analysis.py)[/dim]")
        for resource in results["suspicious_resources"]:
            console.print(f"  [red]{resource['severity']}[/red]: {resource['type']}")
            console.print(f"    Size: {resource['size']} bytes - {resource['reason']}")
        console.print()
    
    # High entropy resources
    if results["high_entropy_resources"]:
        console.print(f"[bold yellow]High Entropy Resources ({len(results['high_entropy_resources'])}):[/bold yellow] [dim](from resource_analysis.py)[/dim]")
        for resource in results["high_entropy_resources"][:RESOURCE_ANALYSIS_CONFIG['high_entropy_display_limit']]:  # Show top 5
            console.print(f"  Size: {resource['size']} bytes (entropy: {resource['entropy']:.2f})")
            console.print(f"    {resource['reason']}")
        console.print()
    
    if results["severity"] == "CRITICAL":
        console.print(f"[bold red][!] Resource severity: CRITICAL[/bold red]\n")
    elif results["severity"] == "HIGH":
        console.print(f"[red][i] Resource severity: HIGH[/red]\n")
    elif results["severity"] == "MEDIUM":
        console.print(f"[yellow][i] Resource severity: MEDIUM[/yellow]\n")
    else:
        console.print(f"[green][OK] Resource severity: LOW[/green]\n")
    
    return results
