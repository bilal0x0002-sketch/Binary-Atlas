"""
Core report builder that orchestrates section building and export.

Handles:
- Section assembly from analysis results
- Format delegation to specific formatters
- File writing and reporting
"""

import os
from datetime import datetime
from typing import Dict, List, Any, Tuple, Optional
from rich.console import Console

from .html_formatter import HTMLFormatter
from .txt_formatter import TXTFormatter
from .formatters import JSONFormatter, CSVFormatter


class ReportBuilder:
    """Unified report generation and orchestration."""
    
    def __init__(self, output_dir: str = "output", timestamp_format: str = "%Y%m%d_%H%M%S"):
        self.output_dir = output_dir
        self.timestamp_format = timestamp_format
        self.dll_imports_data: Dict[str, List[str]] = {}
        self.indicators_dict: Dict[str, List[str]] = {}
        os.makedirs(output_dir, exist_ok=True)
    
    @staticmethod
    def build_sections(
        file_path: str,
        file_size: int,
        file_hashes: Dict,
        imphash: str,
        subsystem_info: Dict,
        manifest_info: Dict,
        threat_indicators: List,
        yara_hits: int,
        found_suspicious_api: bool,
        packer_detected: Any,
        import_anomaly_score: int,
        entropy_count: int,
        risk_level: str,
        risk_desc: str,
        critical_findings: List,
        high_findings: List,
        medium_findings: List,
        is_packed: bool,
        packer_names: List,
        has_c2: bool,
        has_persistence: bool,
        persistence_methods: List,
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
        full_analysis_text: str = "",
        dll_imports_data: Dict = None,
    ) -> List[Dict]:
        """
        Build all report sections from analysis results.
        
        Args:
            file_path: Path to analyzed PE file
            file_hashes: Dict with MD5, SHA256 hashes
            imphash: Import hash
            subsystem_info: Dict with subsystem details
            manifest_info: Dict with manifest details
            threat_indicators: List of threat level strings
            yara_hits: Number of YARA rule matches
            found_suspicious_api: Boolean for suspicious imports
            packer_detected: List of packer names or dict
            import_anomaly_score: 0-100 anomaly score
            entropy_count: Number of high-entropy strings
            risk_level: Final risk level string
            risk_desc: Risk description
            critical_findings: List of critical findings
            high_findings: List of high findings
            medium_findings: List of medium findings
            is_packed: Boolean for packing
            packer_names: List of packer names
            has_c2: Boolean for C2
            has_persistence: Boolean for persistence
            persistence_methods: List of persistence methods
            has_anti_analysis: Boolean for anti-analysis
            has_shellcode: Boolean for shellcode
            shellcode_indicators: Count of shellcode
            complexity_score: 0-6 complexity score
            recommendation: Recommendation string
            rec_detail: Recommendation detail
        
        Returns:
            List of section dictionaries
        """
        sections = []
        
        return sections
    
    def export_report(
        self,
        sections: List[Dict],
        file_path: str,
        formats: Optional[List[str]] = None,
        display_console: Optional[Console] = None,
        full_analysis_output: Optional[str] = None,
    ) -> Tuple[List[str], List[str]]:
        """
        Export report to multiple formats.
        
        Args:
            sections: Report sections from build_sections()
            file_path: Path to analyzed PE file
            formats: List of formats ('txt', 'html', 'json', 'csv')
            display_console: Console for progress output
            full_analysis_output: Full text from analysis
        
        Returns:
            Tuple of (successful_files, failed_files)
        """
        if formats is None:
            formats = ['txt', 'html']
        
        if display_console is None:
            display_console = Console()
        
        full_output = full_analysis_output or ""
        
        # Get file base name
        base_name = os.path.basename(file_path)
        base_name_no_ext = os.path.splitext(base_name)[0]
        timestamp = datetime.now().strftime(self.timestamp_format)
        
        successful = []
        failed = []
        
        # TXT format
        if 'txt' in formats:
            try:
                txt_file = os.path.join(
                    self.output_dir,
                    f"{base_name_no_ext}_analysis_{timestamp}.txt"
                )
                formatter = TXTFormatter(self.indicators_dict)
                txt_content = formatter.format(sections, full_output)
                with open(txt_file, 'w', encoding='utf-8') as f:
                    f.write(txt_content)
                successful.append(txt_file)
                display_console.print(f"[green][OK] Text report: {txt_file}[/green]")
            except Exception as e:
                failed.append(f"TXT: {e}")
                display_console.print(f"[red][X] TXT export failed: {e}[/red]")
        
        # HTML format
        if 'html' in formats:
            try:
                html_file = os.path.join(
                    self.output_dir,
                    f"{base_name_no_ext}_analysis_{timestamp}.html"
                )
                formatter = HTMLFormatter(self.dll_imports_data, self.indicators_dict)
                html_content = formatter.format(sections, full_output)
                with open(html_file, 'w', encoding='utf-8') as f:
                    f.write(html_content)
                successful.append(html_file)
                display_console.print(f"[green][OK] HTML report: {html_file}[/green]")
            except Exception as e:
                failed.append(f"HTML: {e}")
                display_console.print(f"[red][X] HTML export failed: {e}[/red]")
        
        # JSON format
        if 'json' in formats:
            try:
                json_file = os.path.join(
                    self.output_dir,
                    f"{base_name_no_ext}_analysis_{timestamp}.json"
                )
                formatter = JSONFormatter(self.dll_imports_data, self.indicators_dict)
                json_content = formatter.format(sections, full_output)
                with open(json_file, 'w', encoding='utf-8') as f:
                    f.write(json_content)
                successful.append(json_file)
                display_console.print(f"[green][OK] JSON report: {json_file}[/green]")
            except Exception as e:
                failed.append(f"JSON: {e}")
                display_console.print(f"[red][X] JSON export failed: {e}[/red]")
        
        # CSV format
        if 'csv' in formats:
            try:
                csv_file = os.path.join(
                    self.output_dir,
                    f"{base_name_no_ext}_analysis_{timestamp}.csv"
                )
                formatter = CSVFormatter()
                csv_content = formatter.format(sections)
                with open(csv_file, 'w', encoding='utf-8', newline='') as f:
                    f.write(csv_content)
                successful.append(csv_file)
                display_console.print(f"[green][OK] CSV report: {csv_file}[/green]")
            except Exception as e:
                failed.append(f"CSV: {e}")
                display_console.print(f"[red][X] CSV export failed: {e}[/red]")
        
        return successful, failed
