"""
Modular configuration package for PE Analyzer.

This package organizes configuration by module for better maintainability:
- risk_scoring_config.py: Risk scoring thresholds
- indicators_config.py: IOC extraction patterns
- imports_config.py: Import analysis keywords
- packer_config.py: Packer detection configuration
- overlay_analysis_config.py: Overlay analysis configuration
- import_anomaly_config.py: Import anomaly detection
- dll_hijacking_config.py: DLL hijacking detection
- com_hijacking_config.py: COM hijacking detection
- anti_analysis_config.py: Anti-analysis techniques detection (includes privilege/token patterns)
- persistence_detection_config.py: Persistence patterns
- mutex_signatures_config.py: Malware mutex signatures
- pattern_matching_config.py: Malware pattern matching
- resource_analysis_config.py: Resource analysis configuration
- shellcode_detection_config.py: Shellcode detection patterns
- string_entropy_config.py: String entropy analysis
- sections_config.py: Section analysis and packing detection
- filters_config.py: Benign domain filtering
- logger_config.py: Logging and output configuration
- utils_config.py: Utility functions configuration
- yara_scanner_config.py: YARA scanner configuration
"""

