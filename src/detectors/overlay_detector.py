# overlay_analysis.py
"""
Overlay Analysis Module

Detects and analyzes overlay sections - data appended after the PE file's
declared file size.

Overlays are often used by malware to:
- Store encrypted payloads
- Hide additional stages
- Embed configuration data
- Evade signature-based detection
- Store C2 infrastructure details

Professional packers and malware frequently use overlays to append
encrypted/compressed stages that are loaded at runtime.
"""

from typing import Dict, Any
from config.overlay_analysis_config import OVERLAY_ANALYSIS_CONFIG
import math
import pefile
from collections import Counter


def find_overlay(file_path: str, pe: pefile.PE) -> Dict:
    """
    Detect if file has overlay data beyond declared PE size.
    
    Args:
        file_path: Path to PE file
        pe: pefile.PE object
        
    Returns:
        Dict with overlay info:
            - has_overlay: Boolean
            - overlay_size: Bytes of overlay data
            - overlay_offset: Where overlay begins
            - file_size: Total file size
            - pe_declared_size: What PE header says
    """
    try:
        with open(file_path, "rb") as f:
            f.seek(0, 2)  # Seek to end
            file_size = f.tell()
    except (IOError, OSError) as e:
        return {"has_overlay": False, "error": f"Could not read file: {e}"}
    except Exception as e:
        return {"has_overlay": False, "error": f"Unexpected error reading file: {e}"}
    
    # Calculate PE's declared size
    # This is SizeOfHeaders + (highest section VA + VirtualSize)
    declared_size = pe.OPTIONAL_HEADER.SizeOfHeaders
    
    if hasattr(pe, "sections"):
        for section in pe.sections:
            # pefile uses Misc_VirtualSize for the virtual size
            section_vsize = section.Misc_VirtualSize if hasattr(section, "Misc_VirtualSize") else section.SizeOfRawData
            section_end = section.VirtualAddress + section_vsize
            if section_end > declared_size:
                declared_size = section_end
    
    # Account for alignment
    file_alignment = pe.OPTIONAL_HEADER.FileAlignment
    if file_alignment == 0:
        file_alignment = 512  # Default if not set
    declared_size = ((declared_size + file_alignment - 1) // file_alignment) * file_alignment
    
    overlay_size = file_size - declared_size
    
    return {
        "has_overlay": overlay_size > 0,
        "overlay_size": overlay_size,
        "overlay_offset": declared_size,
        "file_size": file_size,
        "pe_declared_size": declared_size
    }


def calculate_entropy(data: bytes) -> float:
    """
    Calculate Shannon entropy of data.
    
    Args:
        data: Bytes to analyze
        
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


def analyze_overlay_content(file_path: str, pe: pefile.PE, overlay_info: Dict) -> Dict:
    """
    Analyze the content of overlay data.
    
    Args:
        file_path: Path to PE file
        pe: pefile.PE object
        overlay_info: Result from find_overlay()
        
    Returns:
        Dict with detailed overlay analysis
    """
    results = {
        "overlay_entropy": 0.0,
        "overlay_structure": "Unknown",
        "contains_pe": False,
        "contains_zip": False,
        "contains_text": False,
        "severity": "LOW"
    }
    
    if not overlay_info["has_overlay"]:
        return results
    
    try:
        with open(file_path, "rb") as f:
            f.seek(overlay_info["overlay_offset"])
            overlay_data = f.read(overlay_info["overlay_size"])
    except (IOError, OSError, KeyError, TypeError):
        return results
    
    if not overlay_data:
        return results
    
    # Calculate entropy
    results["overlay_entropy"] = calculate_entropy(overlay_data)
    
    # Get configuration
    entropy_threshold = OVERLAY_ANALYSIS_CONFIG['entropy_encryption_threshold']
    readable_threshold = OVERLAY_ANALYSIS_CONFIG['readable_ascii_threshold']
    sample_size = OVERLAY_ANALYSIS_CONFIG['readable_ascii_sample_size']
    ascii_range = OVERLAY_ANALYSIS_CONFIG['readable_ascii_char_range']
    
    # Analyze first bytes for file signatures
    if len(overlay_data) >= 2:
        magic = overlay_data[:2]
        
        # Check for PE signature
        if magic == b"MZ":
            results["contains_pe"] = True
            results["overlay_structure"] = "Likely PE executable"
            results["severity"] = "CRITICAL"
        
        # Check for ZIP/compressed
        elif overlay_data[:4] == b"PK\x03\x04":
            results["contains_zip"] = True
            results["overlay_structure"] = "ZIP/compressed archive"
            results["severity"] = "HIGH"
        
        # Check for common compression signatures
        elif overlay_data[:2] == b"\x1f\x8b":
            results["overlay_structure"] = "Likely gzip compressed"
            results["severity"] = "MEDIUM"
        
        elif overlay_data[:4] == b"BZh\x39":  # bzip2
            results["overlay_structure"] = "Likely bzip2 compressed"
            results["severity"] = "MEDIUM"
        
        # Check for high entropy indicating encryption
        if results["overlay_entropy"] > entropy_threshold:
            results["overlay_structure"] = "Likely encrypted"
            results["severity"] = "HIGH"
        
        # Check for mostly readable ASCII (suspicious in overlay)
        try:
            sample_data = overlay_data[:sample_size]
            readable = sum(1 for b in sample_data if ascii_range['min'] <= b <= ascii_range['max'])
            if readable > readable_threshold:
                results["contains_text"] = True
                results["overlay_structure"] = "Contains readable text/strings"
        except (TypeError, IndexError) as e:
            # Skip if overlay_data is not iterable or too small
            pass
        except Exception as e:
            pass
    
    return results


def display_overlay_analysis(file_path: str, pe: pefile.PE, console: Any) -> None:
    """
    Display overlay analysis in formatted output.
    
    Args:
        file_path: Path to PE file
        pe: pefile.PE object
        console: Rich Console for output
    """
    console.print("\n[bold cyan]Overlay Analysis[/bold cyan]")
    console.print("[dim]Detecting data appended beyond PE file boundaries[/dim]\n")
    
    overlay_info = find_overlay(file_path, pe)
    
    if not overlay_info.get("has_overlay", False):
        console.print("[green][OK] No overlay detected (clean PE boundaries)[/green]\n")
        return overlay_info
    
    console.print(f"[bold yellow][!] Overlay detected![/bold yellow]")
    console.print(f"  File size: {overlay_info['file_size']:,} bytes")
    console.print(f"  PE declared size: {overlay_info['pe_declared_size']:,} bytes")
    console.print(f"  Overlay size: {overlay_info['overlay_size']:,} bytes ({(overlay_info['overlay_size']/overlay_info['file_size']*100):.1f}%)\n")
    
    # Analyze overlay content
    content_analysis = analyze_overlay_content(file_path, pe, overlay_info)
    
    console.print(f"[bold yellow]Overlay Content Analysis:[/bold yellow]")
    console.print(f"  Structure: {content_analysis['overlay_structure']}")
    console.print(f"  Entropy: {content_analysis['overlay_entropy']:.2f}/8.0")
    
    if content_analysis["contains_pe"]:
        console.print("  [bold red][!] Contains embedded PE file![/bold red]")
        console.print("    Possible multi-stage malware or dropper (from overlay_analysis.py)")
    
    if content_analysis["contains_zip"]:
        console.print("  [yellow]Contains compressed archive (from overlay_analysis.py)[/yellow]")
    
    if content_analysis["contains_text"]:
        console.print("  [yellow]Contains readable text data (from overlay_analysis.py)[/yellow]")
    
    if content_analysis["overlay_entropy"] > 7.0:
        console.print(f"  [bold red]High entropy ({content_analysis['overlay_entropy']:.2f}) indicates encryption (from overlay_analysis.py)[/bold red]")
    
    console.print(f"  [dim]Overall analysis source: overlay_analysis.py[/dim]")
    
    return {**overlay_info, **content_analysis}
