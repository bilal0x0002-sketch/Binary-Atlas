"""
Detectors Module

Malware detection and analysis modules for identifying:
- Packing and obfuscation
- Shellcode patterns
- Resource anomalies
- Overlay detection
- Persistence mechanisms
- Anti-analysis techniques
- DLL and COM hijacking
- Import anomalies
- Mutex signatures
- Behavior classification
- Pattern matching
"""

from src.detectors.packer_detector import detect_advanced_packing
from src.detectors.shellcode_detector import detect_shellcode
from src.detectors.persistence_detector import detect_persistence_mechanisms
from src.detectors.anti_analysis_detector import detect_anti_analysis
from src.detectors.dll_hijacking_detector import detect_dll_hijacking
from src.detectors.com_hijacking_detector import detect_com_hijacking
from src.detectors.mutex_detector import detect_mutex_signatures
from src.detectors.yara_scanner import load_yara_rules, scan_with_yara

__all__ = [
    "detect_advanced_packing",
    "detect_shellcode",
    "detect_persistence_mechanisms",
    "detect_anti_analysis",
    "detect_dll_hijacking",
    "detect_com_hijacking",
    "detect_mutex_signatures",
    "load_yara_rules",
    "scan_with_yara",
]
