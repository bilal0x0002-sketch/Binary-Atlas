"""
Reporting Module

Report generation, formatting, and threat assessment:
- Threat level assessment
- Findings aggregation by severity
- Executive summary building
- Result extraction and unpacking
- Report generation and export
- JSON, CSV, HTML, and TXT formatters
"""

from src.reporting.threat_assessor import assess_threat_level
from src.reporting.summary_builder import build_summary, format_summary_details
from src.reporting.results_extractor import extract_module_results, extract_advanced_results
from src.reporting.report_generator import generate_reports
from src.reporting.builder import ReportBuilder
from src.reporting.formatters import JSONFormatter, CSVFormatter
from src.reporting.html_formatter import HTMLFormatter
from src.reporting.txt_formatter import TXTFormatter

__all__ = [
    "assess_threat_level",
    "build_summary",
    "format_summary_details",
    "extract_module_results",
    "extract_advanced_results",
    "generate_reports",
    "ReportBuilder",
    "JSONFormatter",
    "CSVFormatter",
    "HTMLFormatter",
    "TXTFormatter",
]
