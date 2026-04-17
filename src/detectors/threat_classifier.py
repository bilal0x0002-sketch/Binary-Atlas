# threat_classifier.py
"""
Unified Threat Classification Module

Merges behavioral analysis and pattern matching into a single integrated detector.
Eliminates redundancy by analyzing APIs once and correlating them against both
behavior definitions and known malware patterns.

Key Features:
- Single pass API extraction and analysis
- Combined behavior + pattern matching confidence scoring
- Deduplication of findings across methods
- Evidence source tracking (Import Table, YARA, Patterns)
- Professional, concise threat reporting
"""

import pefile
import sys
import os
from typing import Any, List, Optional, Dict, Tuple

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../../'))
from config.threat_classification_config import (
    BEHAVIOR_CONFIG, PATTERN_MATCHING_CONFIG, INDICATOR_DETECTION_RULES,
    TASK_SCHEDULER_APIS, TASK_SCHEDULER_STRINGS, STARTUP_REGISTRY_KEYS
)
from src.utils.utils import is_windows_trusted_signature


# Semantic threat name mapping for deduplication
# Maps different detector outputs to canonical threat names
SEMANTIC_THREAT_MAP = {
    # Privilege Escalation
    "privilege_escalation": "privilege_escalation",
    "privilege escalation": "privilege_escalation",
    "yara_privilege": "privilege_escalation",
    
    # Keylogging / Screen Capture
    "keylogging": "keylogging",
    "screen_capture": "keylogging",
    "screen capture": "keylogging",
    "yara_keylog": "keylogging",
    
    # Anti-Analysis / Anti-Debug
    "anti_analysis": "anti_analysis",
    "anti_analysis_evasion_detected": "anti_analysis",
    "anti-analysis": "anti_analysis",
    "anti-debug": "anti_analysis",
    "anti_debug": "anti_analysis",
    "yara_anti": "anti_analysis",
    
    # Dynamic API Loading
    "dynamic_api": "dynamic_api",
    "dynamic api loading": "dynamic_api",
    "dynamic_loading": "dynamic_api",
    
    # Code / Memory Injection / Hooks (all code manipulation)
    "code_injection": "code_injection",
    "memory_injection": "code_injection",
    "code/memory": "code_injection",
    "injection": "code_injection",
    "yara_inject": "code_injection",
    "yara_hooks": "code_injection",
    "hooks": "code_injection",
    "hooks_and_detours": "code_injection",
    "hook_detection": "code_injection",
    "detours": "code_injection",
    
    # Encryption / Multi-stage / High-Entropy / Overlays (all obfuscation variants)
    "encryption": "encryption",
    "encrypted_strings": "encryption",
    "encrypted/high-entropy": "encryption",
    "high_entropy": "encryption",
    "multi_stage": "encryption",
    "multi_stage_payload": "encryption",
    "string_encryption": "encryption",
    "obfuscation": "encryption",
    "overlay": "encryption",
    "overlay_detection": "encryption",
    "overlay detected": "encryption",
    "yara_overlay": "encryption",
    
    # C2 / Communication / Command Execution
    "c2": "c2_communication",
    "c2_communication": "c2_communication",
    "command_and_control": "c2_communication",
    "yara_c2": "c2_communication",
    "command_execution": "c2_communication",
    "cryptographic_c2": "c2_communication",
    
    # File Operations (all file manipulation)
    "file_operations": "file_operations",
    "file operation": "file_operations",
    "file_deletion": "file_operations",
    "file deletion": "file_operations",
    "file_exfiltration": "file_operations",
    "file exfiltration": "file_operations",
    
    # Process Execution / Creation
    "process_execution": "process_execution",
    "process creation": "process_execution",
    "process_creation": "process_execution",
    "yara_process": "process_execution",
    
    # Packing / Polymorphic
    "packer": "packing",
    "packing": "packing",
    "packer_detected": "packing",
    "packer_generic": "packing",
    "packing/obfuscation": "packing",
    "polymorphic": "packing",
    "yara_upx": "packing",
    
    # Registry Operations
    "registry": "registry",
    "registry_operations": "registry",
    "registry_operation": "registry",
    
    # Persistence
    "persistence": "persistence",
    "persistence_method": "persistence",
    "persistence_mechanisms": "persistence",
    "persistence detected": "persistence",
    
    # DLL/COM Hijacking
    "dll_hijacking": "dll_hijacking",
    "com_hijacking": "dll_hijacking",
    "hijacking": "dll_hijacking",
    
    # Shellcode
    "shellcode": "shellcode",
    "shellcode_detected": "shellcode",
    
    # Import Anomalies
    "import_anomalies": "import_anomalies",
    "import_table": "import_anomalies",
    
    # Mutex
    "mutex": "mutex",
    "mutex_detection": "mutex",
    
    # Reconnaissance / Surveillance / RAT
    "reconnaissance": "reconnaissance",
    "surveillance": "surveillance",
    "rat_activity": "rat_activity",
}


def normalize_threat_name(name: str) -> str:
    """
    Normalize threat name to canonical form for semantic deduplication.
    
    Maps different detector outputs to a single canonical name so that
    the same threat detected by different methods gets merged into one finding.
    """
    if not name:
        return ""
    
    # Lowercase and basic cleanup
    normalized = name.lower().strip()
    
    # Remove prefixes
    if normalized.startswith("yara:"):
        normalized = normalized[5:].strip()
    if normalized.startswith("yara_"):
        normalized = normalized[5:].strip()
    
    # Check direct mapping
    if normalized in SEMANTIC_THREAT_MAP:
        return SEMANTIC_THREAT_MAP[normalized]
    
    # Check if it contains keywords
    for keyword, canonical in SEMANTIC_THREAT_MAP.items():
        if keyword in normalized or normalized in keyword:
            return canonical
    
    # Return as-is if no mapping found (fallback)
    return normalized


class ThreatClassifier:
    """
    Unified threat classification from imported APIs.
    
    Combines behavioral analysis and pattern matching into single integrated detection.
    Analyzes PE imports once and generates both behavior classification and pattern
    matching scores in a single pass.
    """
    
    def __init__(self, pe: pefile.PE, console: Any):
        """Initialize threat classifier."""
        self.pe = pe
        self.console = console
        self.extracted_apis = []
        self.extracted_dlls = []
        self.behaviors = {}
        self.patterns = {}
        self.indicators = {}
        
    def extract_apis_and_indicators(self, analysis_results: Dict) -> Dict:
        """
        Extract all APIs and indicators from PE and analysis results.
        Single-pass extraction used by both behavior and pattern matching.
        
        Returns:
            Dict with normalized indicators for pattern matching
        """
        indicators = {
            "functions": [],
            "dlls": [],
            "high_entropy_strings": False,
            "embedded_pe": False,
            "high_overlay_entropy": False,
            "encrypted_strings": False,
            "dynamic_loading": False,
            "registry_ops": False,
            "network_apis": False,
            "process_creation": False
        }
        
        # Extract APIs from import table
        if hasattr(self.pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in self.pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.decode(errors="ignore").upper()
                for imp in entry.imports:
                    api_name = imp.name.decode(errors="ignore") if imp.name else f"ORD_{imp.ordinal}"
                    self.extracted_apis.append(api_name)
                    self.extracted_dlls.append(dll_name)
                    indicators["functions"].append(api_name)
                    if dll_name not in indicators["dlls"]:
                        indicators["dlls"].append(dll_name)
        
        # Extract from analysis results
        if "import_anomalies" in analysis_results:
            indicators["dynamic_loading"] = analysis_results["import_anomalies"].get("dynamic_loading_detected", False)
        
        if "string_entropy" in analysis_results:
            indicators["high_entropy_strings"] = analysis_results["string_entropy"].get("critical_encrypted", 0) > 0
            indicators["encrypted_strings"] = analysis_results["string_entropy"].get("high_entropy_count", 0) > 0
        
        if "resource_analysis" in analysis_results:
            indicators["embedded_pe"] = analysis_results["resource_analysis"].get("embedded_pe_count", 0) > 0
        
        if "overlay_analysis" in analysis_results:
            overlay = analysis_results["overlay_analysis"]
            overlay_threshold = PATTERN_MATCHING_CONFIG['overlay_entropy_threshold']
            indicators["high_overlay_entropy"] = overlay.get("overlay_entropy", 0) > overlay_threshold
        
        # Check for risk indicator combinations
        functions_set = set(indicators["functions"])
        registry_apis_set = set(INDICATOR_DETECTION_RULES['registry_operations'])
        network_apis_set = set(INDICATOR_DETECTION_RULES['network_apis'])
        process_creation_apis_set = set(INDICATOR_DETECTION_RULES['process_creation'])
        
        indicators["registry_ops"] = bool(functions_set & registry_apis_set)
        indicators["network_apis"] = bool(functions_set & network_apis_set)
        indicators["process_creation"] = bool(functions_set & process_creation_apis_set)
        
        self.indicators = indicators
        return indicators
    
    def classify_behaviors(self, indicators_dict: Optional[Dict] = None) -> Dict[str, Dict]:
        """
        Classify malware behaviors from API imports.
        
        Returns:
            Dict of detected behaviors with severity and evidence
        """
        behaviors = {}
        behavior_map = BEHAVIOR_CONFIG['behavior_map']
        
        if hasattr(self.pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in self.pe.DIRECTORY_ENTRY_IMPORT:
                dll = entry.dll.decode(errors="ignore").upper()
                for imp in entry.imports:
                    api = imp.name.decode(errors="ignore") if imp.name else f"ORD_{imp.ordinal}"
                    
                    # Check DLL-specific behaviors
                    if dll in behavior_map and api in behavior_map[dll]:
                        behavior_name, severity = behavior_map[dll][api]
                        if behavior_name not in behaviors:
                            behaviors[behavior_name] = {
                                "apis": [],
                                "severity": severity,
                                "sources": ["IMPORT_TABLE"]
                            }
                        behaviors[behavior_name]["apis"].append(f"{api} ({dll})")
                    
                    # Check global behaviors
                    if api in behavior_map.get("", {}):
                        behavior_name, severity = behavior_map[""][api]
                        if behavior_name not in behaviors:
                            behaviors[behavior_name] = {
                                "apis": [],
                                "severity": severity,
                                "sources": ["IMPORT_TABLE"]
                            }
                        behaviors[behavior_name]["apis"].append(f"{api} ({dll})")
        
        self.behaviors = behaviors
        return behaviors
    
    def match_patterns(self) -> List[Dict]:
        """
        Match extracted indicators against malware patterns.
        
        Returns:
            List of matched patterns with confidence scores
        """
        matched_patterns = []
        malware_patterns = PATTERN_MATCHING_CONFIG['malware_patterns']
        dll_bonus = PATTERN_MATCHING_CONFIG['dll_match_bonus']
        risk_bonus = PATTERN_MATCHING_CONFIG['risk_indicator_bonus']
        
        functions_set = set(self.extracted_apis)
        dlls_set = set(self.extracted_dlls)
        
        for pattern_name, pattern_def in malware_patterns.items():
            confidence = 0
            matched_indicators = []
            
            # Check required functions
            if "required_functions" in pattern_def:
                required = pattern_def["required_functions"]
                matched_funcs = [f for f in required if f in functions_set]
                if matched_funcs:
                    confidence_boost = pattern_def.get('confidence_boost', 10)
                    if len(matched_funcs) == len(required):
                        confidence += confidence_boost
                    else:
                        confidence += confidence_boost * (len(matched_funcs) / len(required))
                    matched_indicators.extend(matched_funcs)
            
            # Check required DLLs
            if "required_dlls" in pattern_def:
                required_dlls = pattern_def["required_dlls"]
                matched_dlls = [d for d in required_dlls if d in dlls_set]
                if matched_dlls:
                    confidence += dll_bonus
                    matched_indicators.extend(matched_dlls)
            
            # Check risk indicators
            if "risk_indicators" in pattern_def:
                for risk_ind in pattern_def["risk_indicators"]:
                    if self.indicators.get(risk_ind, False):
                        confidence += risk_bonus
                        matched_indicators.append(risk_ind)
            
            # Only include if confidence > 0
            if matched_indicators and confidence > 0:
                matched_patterns.append({
                    "name": pattern_name,
                    "confidence": min(confidence, 100),
                    "description": pattern_def["description"],
                    "severity": pattern_def["severity"],
                    "matched_indicators": matched_indicators,
                    "families": pattern_def.get("malware_families", [])
                })
        
        # Sort by confidence
        matched_patterns.sort(key=lambda x: x["confidence"], reverse=True)
        self.patterns = matched_patterns
        return matched_patterns
    
    def generate_unified_report(self, analysis_results: Dict = None) -> Dict:
        """
        Generate unified threat report combining behaviors, patterns, YARA signatures,
        and specialized detectors (persistence, anti-analysis, DLL hijacking, etc).
        
        Args:
            analysis_results: Dict containing results from all detection methods
            
        Returns:
            Dict with consolidated findings from all detection engines
        """
        # ==================== CONTEXT AWARENESS ====================
        # Simple rule: If Windows trusts the signature, it's legitimate
        # If not signed or signature invalid → Analyze as potential malware
        file_path = analysis_results.get("file_path") if analysis_results else None
        
        if file_path:
            # Check if Windows trusts this binary's signature
            is_trusted = is_windows_trusted_signature(file_path)
            
            if is_trusted:
                # Windows verified the signature - it's legitimate
                return {
                    "behaviors": {},
                    "patterns": {},
                    "yara_matches": [],
                    "specialized_detections": {},
                    "threat_level": "LOW",
                    "confidence": 98,
                    "findings": [
                        {
                            "name": "Valid Signature Verified by Windows",
                            "severity": "INFO",
                            "sources": ["Windows Verification"],
                            "indicators": ["Authenticode signature verified as valid"],
                            "detection_count": 1
                        }
                    ],
                    "detection_engines": [],
                    "context_note": "This binary has a valid signature verified by Windows. Trusted and legitimate."
                }
            
            # If we get here, signature is invalid or missing - analyze normally
            # No special handling, treat as potential malware
        
        report = {
            "behaviors": self.behaviors,
            "patterns": self.patterns,
            "yara_matches": [],
            "specialized_detections": {},
            "threat_level": "LOW",
            "confidence": 0,
            "findings": [],
            "detection_engines": []
        }
        
        # Extract YARA matches
        yara_matches = []
        if analysis_results and "yara_matches" in analysis_results:
            yara_list = analysis_results["yara_matches"]
            if isinstance(yara_list, list):
                yara_matches = yara_list
                if "YARA_SCANNER" not in report["detection_engines"]:
                    report["detection_engines"].append("YARA_SCANNER")
        
        report["yara_matches"] = yara_matches
        
        # Extract specialized detections (all detector types)
        specialized_keys = ["anti_analysis", "persistence_detection", "dll_hijacking", "com_hijacking", 
                           "shellcode_detection", "string_entropy", "import_anomalies", "overlay_analysis",
                           "resource_analysis", "mutex_signatures", "packer_detection", "Compiler"]
        
        # Map detector keys to their source names (as they appear in findings)
        source_name_map = {
            "anti_analysis": "ANTI_ANALYSIS_DETECTOR",
            "persistence_detection": "PERSISTENCE_DETECTOR",
            "dll_hijacking": "DLL_HIJACKING_DETECTOR",
            "com_hijacking": "COM_HIJACKING_DETECTOR",
            "shellcode_detection": "SHELLCODE_DETECTOR",
            "string_entropy": "STRING_ENTROPY",
            "import_anomalies": "IMPORT_ANOMALY",
            "overlay_analysis": "OVERLAY_ANALYSIS",
            "resource_analysis": "RESOURCE_ANALYSIS",
            "mutex_signatures": "MUTEX_DETECTOR",
            "packer_detection": "PACKER_DETECTOR",
            "Compiler": "COMPILER_DETECTOR"
        }
        
        for key in specialized_keys:
            if analysis_results and key in analysis_results:
                report["specialized_detections"][key] = analysis_results[key]
                engine_name = source_name_map.get(key, key.upper())
                if engine_name not in report["detection_engines"]:
                    report["detection_engines"].append(engine_name)
        
        # Calculate overall threat level from all sources
        confidence_scores = []
        
        if self.patterns:
            pattern_confidence = sum(p["confidence"] for p in self.patterns) / len(self.patterns)
            confidence_scores.append(pattern_confidence)
            # Behavior & pattern matching merged into threat_classifier - don't list separately
        
        if self.behaviors:
            # Behavior & pattern matching merged into threat_classifier - don't list separately
            # Boost confidence if we have CRITICAL behaviors
            critical_behaviors = [b for b in self.behaviors.values() if b["severity"] == "CRITICAL"]
            if critical_behaviors:
                confidence_scores.append(85)  # High confidence for critical behaviors
        
        if yara_matches:
            if "YARA_SCANNER" not in report["detection_engines"]:
                report["detection_engines"].append("YARA_SCANNER")
            # Filter YARA matches by severity - only HIGH/CRITICAL malware patterns count
            high_confidence_matches = [
                m for m in yara_matches 
                if m.get("severity", "").lower() in ["critical", "high"]
            ]
            # Only count truly malicious rule names (exclude generic API presence detection)
            malicious_keywords = {"ransomware", "trojan", "backdoor", "cryptominer", "rootkit", "worm", "propagat"}
            truly_malicious = [
                m for m in high_confidence_matches
                if any(keyword in m.get("rule", "").lower() for keyword in malicious_keywords)
            ]
            # Score based on HIGH-confidence matches: require multiple suspicious patterns
            if len(truly_malicious) >= 2:
                confidence_scores.append(75)  # Multiple malware families detected
            elif len(truly_malicious) >= 1:
                confidence_scores.append(55)  # One malware family detected
            elif len(high_confidence_matches) >= 3:  # Multiple behavioral anomalies
                confidence_scores.append(45)  # Suspicious but not definitively malware
            # Ignore MEDIUM/LOW severity YARA matches (too many false positives from API presence)
        
        if confidence_scores:
            avg_confidence = sum(confidence_scores) / len(confidence_scores)
            
            malware_threshold = PATTERN_MATCHING_CONFIG['confidence_thresholds']['malware_detected']
            suspicious_threshold = PATTERN_MATCHING_CONFIG['confidence_thresholds']['suspicious_pattern']
            
            if avg_confidence > malware_threshold:
                report["threat_level"] = "CRITICAL"
                report["confidence"] = avg_confidence
            elif avg_confidence > suspicious_threshold:
                report["threat_level"] = "HIGH"
                report["confidence"] = avg_confidence
            elif avg_confidence > 30:
                report["threat_level"] = "MEDIUM"
                report["confidence"] = avg_confidence
            else:
                report["threat_level"] = "LOW"
                report["confidence"] = avg_confidence
        
        # Deduplicate findings across all detection methods using semantic matching
        findings_dedup = {}
        
        # Add from behaviors
        for behavior, data in self.behaviors.items():
            semantic_key = normalize_threat_name(behavior)
            if semantic_key not in findings_dedup:
                findings_dedup[semantic_key] = {
                    "name": behavior,
                    "severity": data["severity"],
                    "sources": ["Behavior Detection"],
                    "indicators": data["apis"][:3],
                    "detection_count": 1
                }
            else:
                # Merge with existing finding
                if "Behavior Detection" not in findings_dedup[semantic_key]["sources"]:
                    findings_dedup[semantic_key]["sources"].append("Behavior Detection")
                    findings_dedup[semantic_key]["detection_count"] += 1
        
        # Add from patterns
        for pattern in self.patterns:
            semantic_key = normalize_threat_name(pattern["name"])
            if semantic_key not in findings_dedup:
                findings_dedup[semantic_key] = {
                    "name": pattern["name"],
                    "severity": pattern["severity"],
                    "sources": ["Pattern Detector"],
                    "confidence": pattern["confidence"],
                    "indicators": pattern["matched_indicators"][:3],
                    "detection_count": 1
                }
            else:
                # Merge with existing finding
                if "Pattern Detector" not in findings_dedup[semantic_key]["sources"]:
                    findings_dedup[semantic_key]["sources"].append("Pattern Detector")
                    findings_dedup[semantic_key]["detection_count"] += 1
                # Keep highest severity
                if pattern["severity"] == "CRITICAL" or findings_dedup[semantic_key]["severity"] != "CRITICAL":
                    findings_dedup[semantic_key]["severity"] = max(
                        pattern["severity"], findings_dedup[semantic_key]["severity"],
                        key=lambda x: {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}.get(x, 0)
                    )
        
        # Add from YARA matches
        for yara_match in yara_matches:
            rule_name = yara_match.get("rule", "UNKNOWN_YARA_RULE")
            semantic_key = normalize_threat_name(rule_name)
            
            # Infer severity from rule name
            rule_name_upper = rule_name.upper()
            if any(x in rule_name_upper for x in ["CRITICAL", "RANSOMWARE", "TROJAN", "BACKDOOR"]):
                severity = "CRITICAL"
            elif any(x in rule_name_upper for x in ["HIGH", "MALWARE", "WORM", "ROOTKIT"]):
                severity = "HIGH"
            else:
                severity = "MEDIUM"
            
            if semantic_key not in findings_dedup:
                findings_dedup[semantic_key] = {
                    "name": rule_name,
                    "severity": severity,
                    "sources": [f"YARA ({rule_name})"],
                    "indicators": [yara_match.get("description", "")],
                    "detection_count": 1
                }
            else:
                # Merge with existing finding
                yara_source = f"YARA ({rule_name})"
                if yara_source not in findings_dedup[semantic_key]["sources"]:
                    findings_dedup[semantic_key]["sources"].append(yara_source)
                    findings_dedup[semantic_key]["detection_count"] += 1
                # Keep highest severity
                severity_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
                if severity_order.get(severity, 0) > severity_order.get(findings_dedup[semantic_key]["severity"], 0):
                    findings_dedup[semantic_key]["severity"] = severity
        
        # Add from specialized detections
        for spec_type, spec_data in report["specialized_detections"].items():
            if not spec_data:
                continue
            
            # Anti-Analysis
            if spec_type == "anti_analysis" and spec_data:
                if any([spec_data.get("anti_debug_apis"), spec_data.get("anti_vm_apis"), 
                       spec_data.get("anti_sandbox_strings"), spec_data.get("anti_emulation_checks")]):
                    semantic_key = normalize_threat_name("anti_analysis")
                    if semantic_key not in findings_dedup:
                        findings_dedup[semantic_key] = {
                            "name": "Anti-Analysis Evasion Detected",
                            "severity": spec_data.get("severity", "HIGH"),
                            "sources": ["Anti-Analysis Detector"],
                            "indicators": (spec_data.get("anti_debug_apis", []) + 
                                         spec_data.get("anti_vm_apis", []))[:3],
                            "detection_count": 1
                        }
                    else:
                        if "Anti-Analysis Detector" not in findings_dedup[semantic_key]["sources"]:
                            findings_dedup[semantic_key]["sources"].append("Anti-Analysis Detector")
                            findings_dedup[semantic_key]["detection_count"] += 1
            
            # Persistence
            elif spec_type == "persistence_detection" and spec_data.get("is_persistent"):
                semantic_key = normalize_threat_name("persistence")
                if semantic_key not in findings_dedup:
                    findings_dedup[semantic_key] = {
                        "name": "Persistence Method Detected",
                        "severity": spec_data.get("severity", "HIGH"),
                        "sources": ["Persistence Detector"],
                        "indicators": spec_data.get("methods_found", [])[:3],
                        "detection_count": 1
                    }
                else:
                    if "Persistence Detector" not in findings_dedup[semantic_key]["sources"]:
                        findings_dedup[semantic_key]["sources"].append("Persistence Detector")
                        findings_dedup[semantic_key]["detection_count"] += 1
            
            # DLL Hijacking
            elif spec_type == "dll_hijacking" and spec_data.get("found"):
                semantic_key = normalize_threat_name("dll_hijacking")
                if semantic_key not in findings_dedup:
                    findings_dedup[semantic_key] = {
                        "name": "DLL Hijacking",
                        "severity": spec_data.get("severity", "HIGH"),
                        "sources": ["DLL Hijacking Detector"],
                        "indicators": spec_data.get("hijacking_methods", [])[:3],
                        "detection_count": 1
                    }
                else:
                    if "DLL Hijacking Detector" not in findings_dedup[semantic_key]["sources"]:
                        findings_dedup[semantic_key]["sources"].append("DLL Hijacking Detector")
                        findings_dedup[semantic_key]["detection_count"] += 1
            
            # COM Hijacking
            elif spec_type == "com_hijacking" and spec_data.get("found"):
                semantic_key = normalize_threat_name("com_hijacking")
                if semantic_key not in findings_dedup:
                    findings_dedup[semantic_key] = {
                        "name": "COM Hijacking",
                        "severity": spec_data.get("severity", "HIGH"),
                        "sources": ["COM Hijacking Detector"],
                        "indicators": spec_data.get("hijacking_methods", [])[:3],
                        "detection_count": 1
                    }
                else:
                    if "COM Hijacking Detector" not in findings_dedup[semantic_key]["sources"]:
                        findings_dedup[semantic_key]["sources"].append("COM Hijacking Detector")
                        findings_dedup[semantic_key]["detection_count"] += 1
            
            # Shellcode
            elif spec_type == "shellcode_detection" and spec_data.get("found"):
                semantic_key = normalize_threat_name("shellcode")
                if semantic_key not in findings_dedup:
                    findings_dedup[semantic_key] = {
                        "name": "Shellcode Detected",
                        "severity": spec_data.get("severity", "HIGH"),
                        "sources": ["Shellcode Detector"],
                        "indicators": spec_data.get("techniques_found", [])[:3],
                        "detection_count": 1
                    }
                else:
                    if "Shellcode Detector" not in findings_dedup[semantic_key]["sources"]:
                        findings_dedup[semantic_key]["sources"].append("Shellcode Detector")
                        findings_dedup[semantic_key]["detection_count"] += 1
            
            # String Entropy
            elif spec_type == "string_entropy" and spec_data:
                if spec_data.get("critical_encrypted", 0) > 0 or spec_data.get("high_entropy_count", 0) > 0:
                    semantic_key = normalize_threat_name("encrypted_strings")
                    if semantic_key not in findings_dedup:
                        findings_dedup[semantic_key] = {
                            "name": "Encrypted/High-Entropy Strings",
                            "severity": "HIGH" if spec_data.get("critical_encrypted", 0) > 0 else "MEDIUM",
                            "sources": ["Entropy Detector"],
                            "indicators": [f"Critical: {spec_data.get('critical_encrypted', 0)}", 
                                         f"High-entropy: {spec_data.get('high_entropy_count', 0)}"],
                            "detection_count": 1
                        }
                    else:
                        if "Entropy Detector" not in findings_dedup[semantic_key]["sources"]:
                            findings_dedup[semantic_key]["sources"].append("Entropy Detector")
                            findings_dedup[semantic_key]["detection_count"] += 1
            
            # Import Anomalies
            elif spec_type == "import_anomalies" and spec_data:
                if spec_data.get("anomaly_score", 0) > 30:
                    semantic_key = normalize_threat_name("import_anomalies")
                    if semantic_key not in findings_dedup:
                        findings_dedup[semantic_key] = {
                            "name": "Import Table Anomalies",
                            "severity": "HIGH" if spec_data.get("anomaly_score", 0) > 50 else "MEDIUM",
                            "sources": ["Import Anomaly Detector"],
                            "indicators": [f"Anomaly score: {spec_data.get('anomaly_score', 0)}%"],
                            "detection_count": 1
                        }
                    else:
                        if "Import Anomaly Detector" not in findings_dedup[semantic_key]["sources"]:
                            findings_dedup[semantic_key]["sources"].append("Import Anomaly Detector")
                            findings_dedup[semantic_key]["detection_count"] += 1
            
            # Overlay Analysis
            elif spec_type == "overlay_analysis" and spec_data:
                if spec_data.get("contains_pe", False) or (spec_data.get("has_overlay", False) and spec_data.get("overlay_entropy", 0) > 7.0):
                    semantic_key = normalize_threat_name("overlay")
                    if semantic_key not in findings_dedup:
                        findings_dedup[semantic_key] = {
                            "name": "Suspicious Overlay Detected",
                            "severity": "CRITICAL" if spec_data.get("contains_pe", False) else "HIGH",
                            "sources": ["Overlay Detector"],
                            "indicators": [f"PE detected" if spec_data.get("contains_pe", False) else f"Entropy: {spec_data.get('overlay_entropy', 0):.2f}"],
                            "detection_count": 1
                        }
                    else:
                        if "Overlay Detector" not in findings_dedup[semantic_key]["sources"]:
                            findings_dedup[semantic_key]["sources"].append("Overlay Detector")
                            findings_dedup[semantic_key]["detection_count"] += 1
            
            # Resource Analysis
            elif spec_type == "resource_analysis" and spec_data:
                if spec_data.get("embedded_pe_count", 0) > 0 or len(spec_data.get("suspicious_resources", [])) > 0:
                    semantic_key = normalize_threat_name("resource")
                    if semantic_key not in findings_dedup:
                        findings_dedup[semantic_key] = {
                            "name": "Suspicious Resources Detected",
                            "severity": "CRITICAL" if spec_data.get("embedded_pe_count", 0) > 0 else "HIGH",
                            "sources": ["Resource Analysis"],
                            "indicators": [f"Embedded PE: {spec_data.get('embedded_pe_count', 0)}", 
                                         f"Suspicious: {len(spec_data.get('suspicious_resources', []))}"],
                            "detection_count": 1
                        }
                    else:
                        if "Resource Analysis" not in findings_dedup[semantic_key]["sources"]:
                            findings_dedup[semantic_key]["sources"].append("Resource Analysis")
                            findings_dedup[semantic_key]["detection_count"] += 1
            
            # Mutex Signatures
            elif spec_type == "mutex_signatures" and spec_data:
                if spec_data.get("severity") in ["HIGH", "CRITICAL"]:
                    semantic_key = normalize_threat_name("mutex")
                    if semantic_key not in findings_dedup:
                        mutex_list = spec_data.get("suspicious_mutexes", []) or spec_data.get("all_mutexes", [])
                        findings_dedup[semantic_key] = {
                            "name": "Known Malware Mutex Detected",
                            "severity": spec_data.get("severity", "HIGH"),
                            "sources": ["Mutex Detector"],
                            "indicators": mutex_list[:3],
                            "detection_count": 1
                        }
                    else:
                        if "Mutex Detector" not in findings_dedup[semantic_key]["sources"]:
                            findings_dedup[semantic_key]["sources"].append("Mutex Detector")
                            findings_dedup[semantic_key]["detection_count"] += 1
            
            # Compiler/Build Info (optional - lower priority)
            elif spec_type == "Compiler" and spec_data:
                if spec_data.get("suspicious_compiler", False):
                    semantic_key = normalize_threat_name("compiler")
                    if semantic_key not in findings_dedup:
                        findings_dedup[semantic_key] = {
                            "name": "Suspicious Compiler/Build Configuration",
                            "severity": "MEDIUM",
                            "sources": ["Compiler Detector"],
                            "indicators": [spec_data.get("compiler_info", "Unknown")],
                            "detection_count": 1
                        }
                    else:
                        if "Compiler Detector" not in findings_dedup[semantic_key]["sources"]:
                            findings_dedup[semantic_key]["sources"].append("Compiler Detector")
                            findings_dedup[semantic_key]["detection_count"] += 1
            
            # Packer Detection
            elif spec_type == "packer_detection" and spec_data:
                if spec_data.get("total_found", 0) > 0:
                    semantic_key = normalize_threat_name("packing")
                    if semantic_key not in findings_dedup:
                        # Build important evidence from packer detection
                        evidence = []
                        if spec_data.get("packer_identified"):
                            evidence.extend(spec_data.get("packer_identified", []))
                        if spec_data.get("entropy_anomalies"):
                            evidence.append(f"Entropy anomalies: {len(spec_data.get('entropy_anomalies', []))}")
                        if spec_data.get("unpacking_stubs"):
                            evidence.append(f"Unpacking stubs: {len(spec_data.get('unpacking_stubs', []))}")
                        if spec_data.get("polymorphic_indicators"):
                            evidence.append(f"Polymorphic indicators: {len(spec_data.get('polymorphic_indicators', []))}")
                        
                        findings_dedup[semantic_key] = {
                            "name": f"Packing/Obfuscation Detected ({spec_data.get('packing_confidence', 'UNKNOWN')})",
                            "severity": spec_data.get("severity", "MEDIUM"),
                            "sources": ["Packer Detector"],
                            "indicators": evidence[:5],
                            "detection_count": 1
                        }
                    else:
                        if "Packer Detector" not in findings_dedup[semantic_key]["sources"]:
                            findings_dedup[semantic_key]["sources"].append("Packer Detector")
                            findings_dedup[semantic_key]["detection_count"] += 1
        
        report["findings"] = list(findings_dedup.values())
        
        # Sort by severity, then by detection count (more sources = higher priority)
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        report["findings"].sort(key=lambda x: (severity_order.get(x["severity"], 4), -x.get("detection_count", 1)))
        
        return report
    
    def display_report(self, report: Dict):
        """Display clean unified threat report as plain text for HTML box."""
        lines = []
        
        # Header
        lines.append("Unified Threat Classification")
        lines.append("")
        lines.append(f"Overall Threat Level: {report['threat_level']}")
        lines.append(f"Detection Confidence: {report['confidence']:.0f}%")
        lines.append(f"Total Threats: {len(report['findings'])} findings")
        lines.append(f"Detection Engines: {', '.join(sorted(report['detection_engines']))}")
        lines.append("")
        
        if not report["findings"]:
            lines.append("No threats detected")
        else:
            # All threats in order
            for i, f in enumerate(report["findings"], 1):
                src = " | ".join(f["sources"])
                evidence = " | ".join(str(x) for x in f.get("indicators", [])[:2]) if f.get("indicators") else "N/A"
                
                lines.append(f"[{i}] {f['severity']} - {f['name']}")
                lines.append(f"Source: {src}")
                lines.append(f"Evidence: {evidence}")
                lines.append("")
        
        # Print as plain text
        output = "\n".join(lines)
        self.console.print(output)
    
    @staticmethod
    def _severity_color(severity: str) -> str:
        """Get color markup for severity level."""
        colors = {
            "CRITICAL": "[bold red]",
            "HIGH": "[bold yellow]",
            "MEDIUM": "[yellow]",
            "LOW": "[green]"
        }
        return colors.get(severity, "[dim]")


def analyze_threats(pe: pefile.PE, console: Any, analysis_results: Dict) -> Dict:
    """
    Main entry point for unified threat classification.
    Combines Behavior Classification + Pattern Matching + YARA Signatures
    into a single integrated threat report.
    
    Args:
        pe: pefile.PE object
        console: Rich Console for output
        analysis_results: Dict from all analysis modules (including yara_matches)
        
    Returns:
        Dict with unified threat report from all detection engines
    """
    classifier = ThreatClassifier(pe, console)
    
    # Single-pass extraction
    indicators = classifier.extract_apis_and_indicators(analysis_results)
    
    # Parallel analysis across all detection methods
    classifier.classify_behaviors()
    classifier.match_patterns()
    
    # Generate unified report combining all sources
    report = classifier.generate_unified_report(analysis_results)
    
    # Display professional consolidated report
    classifier.display_report(report)
    
    return report
