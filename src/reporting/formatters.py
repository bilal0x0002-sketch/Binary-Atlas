"""
Structured data format exporters (JSON and CSV).

JSON: Complete structured data export
CSV: Tabular format for spreadsheet import
"""

import json
import csv
from io import StringIO
from typing import Dict, List


class JSONFormatter:
    """Format report as JSON."""
    
    def __init__(self, dll_imports_data: Dict = None, indicators_dict: Dict = None):
        self.dll_imports_data = dll_imports_data or {}
        self.indicators_dict = indicators_dict or {}
    
    def format(self, sections: List[Dict], full_output: str = "") -> str:
        """Generate JSON report."""
        from datetime import datetime
        
        payload = {
            "metadata": {
                "timestamp": datetime.now().isoformat(),
                "report_type": "pe_malware_analysis",
                "schema_version": "1.0",
            },
            "sections": sections,
        }
        
        if self.dll_imports_data:
            payload["dll_imports"] = self.dll_imports_data
        
        if self.indicators_dict:
            payload["indicators"] = self.indicators_dict
        
        if full_output:
            payload["raw_output"] = full_output
        
        return json.dumps(payload, indent=2, ensure_ascii=False)


class CSVFormatter:
    """Format report as CSV."""
    
    def format(self, sections: List[Dict]) -> str:
        """Generate CSV report."""
        buf = StringIO()
        writer = csv.writer(buf)
        
        writer.writerow(["section_type", "section_title", "key", "value"])
        
        for section in sections:
            for key, value in section.items():
                if isinstance(value, (dict, list)):
                    value_str = json.dumps(value, ensure_ascii=False)
                else:
                    value_str = "" if value is None else str(value)
                
                writer.writerow([
                    section.get("type", "unknown"),
                    section.get("title", ""),
                    key,
                    value_str
                ])
        
        return buf.getvalue()
