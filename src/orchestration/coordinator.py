"""
Single file analysis coordinator.

Orchestrates all analysis stages: PE loading, analysis execution, result extraction,
threat assessment, finding aggregation, and reporting.
"""

from io import StringIO
from rich.console import Console
from typing import Tuple

from src.utils.utils import load_pe_file
from src.utils.provenance import calculate_file_hashes, get_imphash, get_manifest_info, check_subsystem_privileges
from src.utils.whitelist import get_whitelist_report_note
from src.utils.colors import C
from src.utils.output_formatter import OutputFormatter

from src.orchestration.engine import run_core_analysis, run_advanced_analysis
from src.reporting.results_extractor import extract_module_results, extract_advanced_results
from src.reporting.summary_builder import build_summary, format_summary_details
from src.reporting.report_generator import generate_reports

from config.logger_config import OUTPUT_WIDTH


def analyze_file(path: str, output_dir: str, args, display_console: Console) -> Tuple[bool, str]:
    """
    Analyze a single PE file: execution, extraction, assessment, and reporting.
    
    Returns (success: bool, message: str)
    """
    
    # ==================== SETUP ====================
    text_buffer = StringIO()
    display_only = Console()
    output_console = Console(file=text_buffer, width=OUTPUT_WIDTH, force_terminal=False)
    
    class DualConsoleWrapper:
        def __init__(self, buffer_console, display_console):
            self.buffer_console = buffer_console
            self.display_console = display_console
        def print(self, *args, **kwargs):
            self.buffer_console.print(*args, **kwargs)
            self.display_console.print(*args, **kwargs)
    
    output_console = DualConsoleWrapper(output_console, display_only)
    formatter = OutputFormatter(output_console)
    
    # ==================== LOAD PE ====================
    try:
        pe = load_pe_file(path)
        if not pe:
            return False, f"Failed to load PE file: {path}"
    except Exception as e:
        return False, f"Error loading PE file {path}: {e}"
    
    try:
        # ==================== WELCOME ====================
        formatter.print_welcome(path)
        whitelist_note = get_whitelist_report_note(path)
        if whitelist_note:
            formatter.print_whitelist_note(whitelist_note)
        
        file_hashes = {}
        if not args.no_hash:
            file_hashes = calculate_file_hashes(path)
        
        imphash = get_imphash(pe)
        formatter.print_file_identification(path, file_hashes, imphash, no_hash_mode=args.no_hash)
        
        subsystem_info = check_subsystem_privileges(pe)
        manifest_info = get_manifest_info(pe)
        formatter.print_privilege_context(subsystem_info, manifest_info)
        
        if args.verbose:
            formatter.print_verbose_mode()
        
        # ==================== ANALYSIS EXECUTION ====================
        indicators_dict = {}
        analysis_results = run_core_analysis(pe, output_console, formatter, args, indicators_dict)
        
        threat_indicators = []
        found_suspicious_api, file_size, dll_imports_data = False, 0, {}
        packer_detected = []
        threat_indicators, found_suspicious_api, file_size, indicators_dict, packer_detected, dll_imports_data = extract_module_results(analysis_results)
        
        yara_hits, yara_count, yara_matches = run_advanced_analysis(
            pe, path, output_console, display_console, args, formatter,
            threat_indicators, analysis_results, indicators_dict
        )
        
        # ==================== RESULT EXTRACTION ====================
        import_anomaly_score = analysis_results.get("import_anomalies", {}).get("anomaly_score", 0)
        entropy_count = analysis_results.get("string_entropy", {}).get("high_entropy_count", 0)
        
        # ==================== THREAT ASSESSMENT ====================
        from src.reporting.threat_assessor import assess_threat_level
        risk_level, risk_desc = assess_threat_level(
            threat_indicators, yara_hits, found_suspicious_api,
            packer_detected, import_anomaly_score, entropy_count
        )
        
        threat_color_markup = C.CRITICAL_LEVEL if risk_level == "CRITICAL" else C.HIGH_LEVEL if risk_level == "HIGH" else C.MINIMAL_LEVEL
        threat_color_end = C.CRITICAL_LEVEL_END if risk_level == "CRITICAL" else C.HIGH_LEVEL_END if risk_level == "HIGH" else C.MINIMAL_LEVEL_END
        # Threat level already displayed in Unified Threat Classification report from threat_classifier
        # formatted_risk_level = f"{threat_color_markup}Overall Threat Level: {risk_level}{threat_color_end}"
        # formatter.print_threat_level(formatted_risk_level, risk_desc)
        
        # ==================== FINDINGS ====================
        anti_analysis_dict, shellcode_dict, persistence_dict, dll_hijacking_dict, com_hijacking_dict = extract_advanced_results(analysis_results)
        critical_findings, high_findings, medium_findings = [], [], []
        
        # Initialize indicators and related variables before try-except
        indicators = {"is_packed": False, "has_c2": False, "has_persistence": False, "has_anti_analysis": False}
        complexity_score = 0
        complexity = "BASIC"
        recommendation = ""
        rec_detail = ""
        packer_names = []
        packer_detail = ""
        c2_detail = ""
        persistence_detail = ""
        complexity_color_markup = "[yellow]"
        complexity_color_end = "[/yellow]"
        
        try:
            indicators, complexity_score, complexity, recommendation, rec_detail, packer_names = build_summary(
                yara_hits, packer_detected, persistence_dict, anti_analysis_dict,
                shellcode_dict, dll_hijacking_dict, risk_level, threat_indicators
            )
            
            packer_detail, c2_detail, persistence_detail, complexity_color_markup, complexity_color_end = format_summary_details(
                indicators, yara_hits, packer_names, persistence_dict, complexity_score, complexity
            )
            
            formatter.print_summary_findings(
                indicators["is_packed"], packer_detail, indicators["has_c2"], c2_detail,
                indicators["has_persistence"], persistence_detail, indicators["has_anti_analysis"],
                complexity_score, complexity, complexity_color_markup, complexity_color_end
            )
            formatter.print_recommendation(recommendation, rec_detail)
            formatter.print_completion()
        except UnicodeEncodeError:
            # Silently catch encoding errors from console output (Windows cp1252 encoding issues)
            # Reports will still be generated with full data
            pass
        
        # ==================== REPORTING ====================
        success, message = generate_reports(
            path, output_dir, file_size, file_hashes, imphash, subsystem_info, manifest_info,
            threat_indicators, yara_hits, found_suspicious_api, packer_detected,
            import_anomaly_score, entropy_count, risk_level, risk_desc,
            critical_findings, high_findings, medium_findings, indicators["is_packed"], packer_names,
            indicators["has_c2"], indicators["has_persistence"], persistence_dict.get("methods_found", []),
            indicators["has_anti_analysis"], shellcode_dict.get("total_found", 0) > 0,
            shellcode_dict.get("total_found", 0), dll_hijacking_dict.get("has_hijacking_risk", False),
            len(dll_hijacking_dict.get("suspicious_dlls", [])) + len(dll_hijacking_dict.get("relative_path_strings", [])),
            com_hijacking_dict.get("is_highrisk", False), com_hijacking_dict.get("total_found", 0),
            complexity_score, recommendation, rec_detail, text_buffer, display_console,
            dll_imports_data, indicators_dict
        )
        
        return success, message
    
    except Exception as e:
        import traceback
        try:
            error_msg = str(e)
        except:
            error_msg = "Unknown error during analysis"
        return False, f"Analysis failed: {error_msg}"
