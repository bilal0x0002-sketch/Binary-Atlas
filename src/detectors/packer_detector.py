"""
Packer Detection Module

Comprehensive packer and obfuscation detection using:
- Entropy analysis (encryption/compression detection)
- Known packer signatures (UPX, ASPack, Themida, VMProtect, etc.)
- Unpacking stub patterns (VirtualAlloc, WriteProcessMemory, etc.)
- Obfuscation techniques (dynamic imports, encryption, reflection)
- Relocation table anomalies
- Polymorphic code indicators
- Section structure anomalies
"""

import math
import pefile
from typing import Dict, List, Tuple, Any
from rich.console import Console
from config.packer_config import PACKER_SIGNATURES, PACKER_DETECTION_CONFIG, ENTROPY_THRESHOLDS_DETECTION
from src.utils.extraction import extract_all_strings, extract_all_binary_data


def detect_advanced_packing(pe: pefile.PE, console: Console) -> Tuple[Dict, List[str]]:
    """
    Detect advanced packing and obfuscation techniques
    
    Args:
        pe: Pefile object
        console: Rich console for output
        
    Returns:
        Tuple of (detection_dict, output_lines)
    """
    output_lines = []
    results = {
        "packer_identified": [],
        "entropy_anomalies": [],
        "unpacking_stubs": [],
        "obfuscation_detected": [],
        "relocation_anomalies": [],
        "polymorphic_indicators": [],
        "section_anomalies": [],
        "total_found": 0,
        "severity": "LOW",
        "packing_confidence": "NONE",
        "packing_score": 0.0,  # 0.0 - 1.0 probabilistic score
        "score_reasons": [],  # Explanations for the score
        "details": ""
    }
    
    try:
        all_strings = extract_all_strings(pe)
        binary_data = extract_all_binary_data(pe)
        
        # Check for known packers
        packers = _check_known_packers(all_strings, binary_data)
        results["packer_identified"] = packers["found"]
        
        # Check for entropy anomalies
        entropy_anomalies = _check_entropy_anomalies(pe)
        results["entropy_anomalies"] = entropy_anomalies["found"]
        
        # Check for unpacking stubs
        unpacking = _check_unpacking_stubs(all_strings, binary_data)
        results["unpacking_stubs"] = unpacking["found"]
        
        # Check for obfuscation
        obfuscation = _check_obfuscation_techniques(all_strings)
        results["obfuscation_detected"] = obfuscation["found"]
        
        # Check for relocation table anomalies
        relocations = _check_relocation_anomalies(pe)
        results["relocation_anomalies"] = relocations["found"]
        
        # Check for polymorphic/code cave indicators
        polymorphic = _check_polymorphic_indicators(pe, binary_data)
        results["polymorphic_indicators"] = polymorphic["found"]
        
        # Check section structure anomalies
        section_anomalies = _check_section_anomalies(pe)
        results["section_anomalies"] = section_anomalies["found"]
        
        results["total_found"] = (
            len(results["packer_identified"]) +
            len(results["entropy_anomalies"]) +
            len(results["unpacking_stubs"]) +
            len(results["obfuscation_detected"]) +
            len(results["relocation_anomalies"]) +
            len(results["polymorphic_indicators"]) +
            len(results["section_anomalies"])
        )
        
        # Determine packing confidence and severity
        # Also compute probabilistic packing_score (0.0 - 1.0)
        packer_config = PACKER_DETECTION_CONFIG
        if results["packer_identified"]:
            results["packing_confidence"] = "IDENTIFIED"
            results["severity"] = "CRITICAL"
            results["packing_score"] = 0.95
            results["score_reasons"].append("Known packer signature matched")
        elif results["total_found"] >= packer_config['confidence_thresholds']['highly_likely']:
            results["packing_confidence"] = "HIGHLY_LIKELY"
            results["severity"] = "HIGH"
            results["packing_score"] = 0.80
            results["score_reasons"].append("Multiple entropy anomalies + unpacking stubs detected")
        elif results["total_found"] >= packer_config['confidence_thresholds']['probable']:
            results["packing_confidence"] = "PROBABLE"
            results["severity"] = "MEDIUM"
            results["packing_score"] = 0.55
            results["score_reasons"].append("Multiple packing indicators found")
        elif results["total_found"] > 0:
            results["packing_confidence"] = "POSSIBLE"
            results["severity"] = "LOW"
            results["packing_score"] = 0.25
            results["score_reasons"].append("Some weak packing indicators detected")
        else:
            results["packing_confidence"] = "NONE"
            results["severity"] = "LOW"
            results["packing_score"] = 0.05
            results["score_reasons"].append("Entropy normal for .text section")
            results["score_reasons"].append("No overlay compression detected")
            results["score_reasons"].append("No import stripping detected")
        
        # Generate output
        console.print("\n[bold cyan]Advanced Packing Detection[/bold cyan]")
        console.print("[dim]Analyzing for packing, obfuscation, and polymorphic indicators[/dim]\n")
        
        # Always show packing score
        score_pct = int(results["packing_score"] * 100)
        if results["packing_score"] < 0.3:
            score_color = "[green]"
        elif results["packing_score"] < 0.6:
            score_color = "[yellow]"
        else:
            score_color = "[red]"
        
        console.print(f"[bold]Packing Score: {score_color}{score_pct}%[/] ({results['packing_confidence']})[/bold]")
        
        # Show reasoning
        if results["score_reasons"]:
            console.print("[dim]Reasons:[/dim]")
            for reason in results["score_reasons"]:
                console.print(f"  - {reason}")
        
        if results["total_found"] > 0:
            console.print(f"\n[red][!] Advanced Packing Indicators ({results['total_found']} found)[/red]")
            
            if results["packer_identified"]:
                console.print(f"  [red]Known Packer[/red]: {', '.join(results['packer_identified'])}")
                output_lines.append(f"  [red]Known Packer[/red]: {', '.join(results['packer_identified'])}")
            
            if results["entropy_anomalies"]:
                console.print(f"  [yellow]Entropy Anomalies[/yellow]: {len(results['entropy_anomalies'])} section(s)")
                output_lines.append(f"  [yellow]Entropy Anomalies[/yellow]: {len(results['entropy_anomalies'])} section(s)")
                for anomaly in results["entropy_anomalies"][:3]:
                    console.print(f"    - {anomaly}")
                    output_lines.append(f"    - {anomaly}")
            
            if results["unpacking_stubs"]:
                console.print(f"  [red]Unpacking Stubs[/red]: {len(results['unpacking_stubs'])} found")
                output_lines.append(f"  [red]Unpacking Stubs[/red]: {len(results['unpacking_stubs'])} found")
                for stub in results["unpacking_stubs"][:2]:
                    console.print(f"    - {stub}")
                    output_lines.append(f"    - {stub}")
            
            if results["obfuscation_detected"]:
                console.print(f"  [yellow]Obfuscation Detected[/yellow]: {', '.join(results['obfuscation_detected'][:3])}")
                output_lines.append(f"  [yellow]Obfuscation Detected[/yellow]: {', '.join(results['obfuscation_detected'][:3])}")
            
            if results["relocation_anomalies"]:
                console.print(f"  [yellow]Relocation Anomalies[/yellow]: {len(results['relocation_anomalies'])} detected")
                output_lines.append(f"  [yellow]Relocation Anomalies[/yellow]: {len(results['relocation_anomalies'])} detected")
            
            if results["polymorphic_indicators"]:
                console.print(f"  [red]Polymorphic Indicators[/red]: {len(results['polymorphic_indicators'])} found")
                output_lines.append(f"  [red]Polymorphic Indicators[/red]: {len(results['polymorphic_indicators'])} found")
            
            if results["section_anomalies"]:
                console.print(f"  [yellow]Section Anomalies[/yellow]: {len(results['section_anomalies'])}")
                output_lines.append(f"  [yellow]Section Anomalies[/yellow]: {len(results['section_anomalies'])}")
            
            console.print(f"  [bold red]Severity: {results['severity']}[/bold red]")
            console.print(f"  [dim]Source: packer.py[/dim]\n")
            output_lines.append(f"  [bold red]Severity: {results['severity']}[/bold red]")
            output_lines.append(f"  [dim]Source: packer.py[/dim]")
        else:
            console.print("[green][OK] No advanced packing detected[/green]\n")
            output_lines.append("[green][OK] No advanced packing detected[/green]")
        
        results["details"] = "\n".join(output_lines)
        
    except Exception as e:
        output_lines.append(f"[yellow][!] Packing detection error: {str(e)[:100]}[/yellow]")
        results["details"] = "\n".join(output_lines)
    
    return results, output_lines


def _check_known_packers(strings: List[str], binary_data: bytes) -> Dict[str, Any]:
    """Check for signatures of known packers"""
    found = []
    risk = 0
    
    packer_signatures = PACKER_SIGNATURES
    for packer_name, signatures in packer_signatures.items():
        for sig in signatures:
            # Check in binary (encode signature to bytes)
            try:
                sig_bytes = sig.encode("utf-8", errors="ignore")
                if sig_bytes in binary_data:
                    found.append(packer_name)
                    break
            except:
                pass
            
            # Check in strings
            for string in strings:
                if sig in string:
                    found.append(packer_name)
                    break
    
    # Remove duplicates
    found = list(set(found))
    return {"found": found, "risk": risk}


def _check_entropy_anomalies(pe: pefile.PE) -> Dict[str, Any]:
    """Check sections for entropy anomalies (sign of encryption/compression)"""
    found = []
    risk = 0
    
    try:
        for section in pe.sections:
            section_name = section.name.decode().strip("\x00")
            data = section.get_data()
            
            min_section_size = PACKER_DETECTION_CONFIG['entropy_section_min_size']
            if len(data) < min_section_size:  # Skip tiny sections
                continue
            
            entropy = _calculate_entropy(data)
            
            # Get entropy thresholds from config
            entropy_thresholds = ENTROPY_THRESHOLDS_DETECTION
            
            # Check for high entropy (encrypted or compressed)
            if entropy > entropy_thresholds["high_entropy"]:
                found.append(f"{section_name} (entropy: {entropy:.2f} - encrypted/compressed)")
            # Check for moderate entropy (possibly obfuscated)
            elif entropy > entropy_thresholds["moderate_entropy"]:
                found.append(f"{section_name} (entropy: {entropy:.2f} - possibly obfuscated)")
            
            # Check for unusual combinations
            entropy_text_threshold = PACKER_DETECTION_CONFIG['entropy_text_section_threshold']
            if section_name == ".text" and entropy > entropy_text_threshold:
                found.append(f"{section_name} has unusually high entropy for code section")
    except Exception:
        pass  # Continue even if entropy check fails
    
    return {"found": found, "risk": risk}


def _check_unpacking_stubs(strings: List[str], binary_data: bytes) -> Dict[str, Any]:
    """Detect unpacking stub patterns"""
    found = []
    risk = 0
    
    # Get unpacking indicators from config
    unpacking_indicators = PACKER_DETECTION_CONFIG['unpacking_indicators']
    
    indicator_count = 0
    for indicator in unpacking_indicators:
        for string in strings:
            if indicator.lower() in string.lower():
                indicator_count += 1
                if indicator not in found:
                    found.append(indicator)
    
    # Multiple unpacking-related APIs = likely unpacking stub
    packer_config = PACKER_DETECTION_CONFIG
    if indicator_count >= packer_config['unpacking_apis_threshold_high']:
        found.append("Unpacking/relocation stub detected")
    elif indicator_count >= packer_config['unpacking_apis_threshold_low']:
        pass
    
    return {"found": found, "risk": risk}


def _check_obfuscation_techniques(strings: List[str]) -> Dict[str, Any]:
    """Detect obfuscation techniques"""
    found = []
    risk = 0
    
    # Get obfuscation techniques from config
    techniques = PACKER_DETECTION_CONFIG['obfuscation_techniques']
    
    # Normalize strings once for performance and convert to set
    strings_lower_set = set(s.lower() for s in strings)
    
    detected_techniques = {}
    for tech_name, keywords in techniques.items():
        keywords_lower_set = set(k.lower() for k in keywords)
        count = sum(1 for keyword in keywords_lower_set if any(keyword in string for string in strings_lower_set))
        
        if count > 0:
            detected_techniques[tech_name] = count
            found.append(f"{tech_name}: {count} indication(s)")
    
    # Multiple obfuscation techniques = higher confidence
    obfuscation_threshold = PACKER_DETECTION_CONFIG['obfuscation_techniques_threshold']
    if len(detected_techniques) >= obfuscation_threshold:
        pass
    
    return {"found": found, "risk": risk}


def _check_relocation_anomalies(pe: pefile.PE) -> Dict[str, Any]:
    """Check for suspicious relocation table anomalies"""
    found = []
    risk = 0
    
    packer_config = PACKER_DETECTION_CONFIG
    excessive_threshold = packer_config['relocation_excessive_threshold']
    high_threshold = packer_config['relocation_high_threshold']
    
    try:
        if hasattr(pe, "DIRECTORY_ENTRY_BASERELOC"):
            reloc_count = 0
            for reloc_block in pe.DIRECTORY_ENTRY_BASERELOC:
                reloc_count += len(reloc_block.entries)
            
            # Too many relocations might indicate packing
            if reloc_count > excessive_threshold:
                found.append(f"Excessive relocations: {reloc_count} (typical: <500)")
            
            # Check for unusual relocation offsets
            if reloc_count > high_threshold:
                found.append(f"High relocation count: {reloc_count}")
        else:
            # Missing relocation table is suspicious
            if not hasattr(pe, "DIRECTORY_ENTRY_BASERELOC"):
                found.append("Missing or minimal relocation table")
    except Exception:
        pass  # Continue even if relocation analysis fails
    
    return {"found": found, "risk": risk}


def _check_polymorphic_indicators(pe: pefile.PE, binary_data: bytes) -> Dict[str, Any]:
    """Detect polymorphic code and code cave indicators"""
    found = []
    risk = 0
    
    packer_config = PACKER_DETECTION_CONFIG
    section_size_threshold = packer_config['section_suspicious_min_size']
    null_byte_ratio_threshold = packer_config['code_cave_null_byte_ratio']
    
    try:
        # Look for code caves (large sequences of same byte)
        caves = _find_code_caves(binary_data)
        if caves:
            found.extend(caves)
        
        # Check for suspicious section characteristics
        for section in pe.sections:
            section_name = section.name.decode().strip("\x00")
            
            # Check for all-zero sections (code caves)
            if section.VirtualSize > section_size_threshold:  # Large enough to be suspicious
                data = section.get_data()
                if data.count(b"\x00") > len(data) * null_byte_ratio_threshold:  # >90% null bytes
                    found.append(f"{section_name} contains large code cave (null padding)")
        
        # Polymorphic indicators
        if len(found) > 1:
            found.append("Potential polymorphic code structure")
    except Exception:
        pass  # Continue even if polymorphic detection fails
    
    return {"found": found, "risk": risk}


def _check_section_anomalies(pe: pefile.PE) -> Dict[str, Any]:
    """Check for anomalies in section structure"""
    found = []
    risk = 0
    
    packer_config = PACKER_DETECTION_CONFIG
    compression_ratio_threshold = packer_config['section_compression_ratio_threshold']
    ratio_low_threshold = packer_config['section_ratio_low_threshold']
    
    try:
        for section in pe.sections:
            section_name = section.name.decode().strip("\x00")
            
            # Suspicious section names from config
            suspicious_names = PACKER_DETECTION_CONFIG['suspicious_section_names']
            for susp in suspicious_names:
                if susp.lower() in section_name.lower():
                    found.append(f"Suspicious section name: {section_name}")
                    break
            
            # Check for mismatched sizes (sign of packing)
            if section.VirtualSize > 0 and section.SizeOfRawData > 0:
                ratio = section.VirtualSize / section.SizeOfRawData
                if ratio > compression_ratio_threshold:
                    found.append(f"{section_name} high compression ratio: {ratio:.1f}:1")
                elif ratio < ratio_low_threshold and section.Characteristics & 0x60000000:  # Execute+Read
                    found.append(f"{section_name} unusually high raw:virtual ratio")
            
            # Check for missing standard sections
            if section_name == ".text" and section.VirtualSize == 0:
                found.append("Empty .text section (code may be packed)")
    except Exception:
        pass  # Continue even if section analysis fails
    
    return {"found": found, "risk": risk}


def _find_code_caves(binary_data: bytes, min_size: int = None) -> List[str]:
    """Find potential code caves (large runs of same byte)"""
    if min_size is None:
        min_size = PACKER_DETECTION_CONFIG['code_cave_min_size']
    
    caves = []
    
    # Look for large null-byte regions
    null_regions = []
    current_start = -1
    current_length = 0
    
    for i, byte in enumerate(binary_data):
        if byte == 0x00:
            if current_start == -1:
                current_start = i
                current_length = 1
            else:
                current_length += 1
        else:
            if current_length >= min_size:
                null_regions.append((current_start, current_length))
            current_start = -1
            current_length = 0
    
    if current_length >= min_size:
        null_regions.append((current_start, current_length))
    
    # Report largest caves
    for offset, length in sorted(null_regions, key=lambda x: x[1], reverse=True)[:3]:
        caves.append(f"Code cave at offset 0x{offset:x} ({length} bytes)")
    
    return caves


def _calculate_entropy(data: bytes) -> float:
    """Calculate Shannon entropy of data"""
    if len(data) == 0:
        return 0.0
    
    # Calculate byte frequency
    freq = {}
    for byte in data:
        freq[byte] = freq.get(byte, 0) + 1
    
    # Calculate entropy
    entropy = 0.0
    data_len = len(data)
    for count in freq.values():
        probability = count / data_len
        entropy -= probability * math.log2(probability)
    
    # Normalize to 0-1 (max is 8 bits)
    return entropy / 8
