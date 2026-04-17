"""
Report generation and export coordination.

Builds report sections and exports analysis to TXT and HTML formats.
"""

import os
from typing import Dict, Any, Tuple
from src.reporting.builder import ReportBuilder
from src.utils.colors import C


def generate_reports(
    path: str,
    output_dir: str,
    file_size: int,
    file_hashes: Dict[str, str],
    imphash: str,
    subsystem_info: Dict[str, Any],
    manifest_info: Dict[str, Any],
    threat_indicators: list,
    yara_hits: int,
    found_suspicious_api: bool,
    packer_detected: Any,
    import_anomaly_score: int,
    entropy_count: int,
    risk_level: str,
    risk_desc: str,
    critical_findings: list,
    high_findings: list,
    medium_findings: list,
    is_packed: bool,
    packer_names: list,
    has_c2: bool,
    has_persistence: bool,
    persistence_methods: list,
    has_anti_analysis: bool,
    has_shellcode: bool,
    shellcode_indicators: int,
    has_dll_hijacking: bool,
    dll_hijacking_count: int,
    has_com_hijacking: bool,
    com_hijacking_count: int,
    complexity_score: int,
    recommendation: str,
    rec_detail: str,
    text_buffer: Any,
    display_console: Any,
    dll_imports_data: Dict[str, Any],
    indicators_dict: Dict[str, Any]
) -> Tuple[bool, str]:
    """
    Generate and export analysis reports.
    
    Returns (success: bool, message: str)
    """
    try:
        try:
            file_size = os.path.getsize(path)
        except:
            file_size = 0
        
        # Build report sections
        sections = ReportBuilder.build_sections(
            file_path=path,
            file_size=file_size,
            file_hashes=file_hashes,
            imphash=imphash,
            subsystem_info=subsystem_info,
            manifest_info=manifest_info,
            threat_indicators=threat_indicators,
            yara_hits=yara_hits,
            found_suspicious_api=found_suspicious_api,
            packer_detected=packer_detected,
            import_anomaly_score=import_anomaly_score,
            entropy_count=entropy_count,
            risk_level=risk_level,
            risk_desc=risk_desc,
            critical_findings=critical_findings,
            high_findings=high_findings,
            medium_findings=medium_findings,
            is_packed=is_packed,
            packer_names=packer_names,
            has_c2=has_c2,
            has_persistence=has_persistence,
            persistence_methods=persistence_methods,
            has_anti_analysis=has_anti_analysis,
            has_shellcode=has_shellcode,
            shellcode_indicators=shellcode_indicators,
            has_dll_hijacking=has_dll_hijacking,
            dll_hijacking_count=dll_hijacking_count,
            has_com_hijacking=has_com_hijacking,
            com_hijacking_count=com_hijacking_count,
            complexity_score=complexity_score,
            recommendation=recommendation,
            rec_detail=rec_detail,
            full_analysis_text="",
            dll_imports_data=dll_imports_data
        )
        
        # Export to TXT and HTML
        reporter = ReportBuilder(output_dir=output_dir)
        reporter.dll_imports_data = dll_imports_data
        reporter.indicators_dict = indicators_dict
        
        full_output = text_buffer.getvalue()
        successful, failed = reporter.export_report(sections, path, ['txt', 'html'], display_console, full_output)
        
        if successful:
            try:
                display_console.print(f"\n{C.SUCCESS}[OK] Reports generated successfully{C.SUCCESS_END}")
            except:
                pass
            return True, "Analysis complete"
        else:
            try:
                display_console.print(f"{C.ERROR}[X] Report export failed: {failed}{C.ERROR_END}")
            except:
                pass
            return False, f"Report export failed: {failed}"
    
    except Exception as e:
        try:
            display_console.print(f"{C.ERROR}[X] Error generating reports: {e}{C.ERROR_END}")
        except:
            pass
        return False, f"Error generating reports: {e}"
