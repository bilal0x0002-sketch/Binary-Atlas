"""
Plain text report formatter.

Generates clean, readable text reports with:
- Full analysis console output
- Structured sections
- String indicators summary
"""

from typing import Dict, List
from .utils import strip_rich_markup


class TXTFormatter:
    """Format report sections as plain text."""
    
    def __init__(self, indicators_dict: Dict = None):
        self.indicators_dict = indicators_dict or {}
    
    def format(self, sections: List[Dict], full_output: str = "") -> str:
        """Generate plain text report."""
        lines = []
        
        if full_output:
            lines.append(full_output)
            lines.append("\n" + "=" * 70)
            lines.append("STRUCTURED ANALYSIS SUMMARY")
            lines.append("=" * 70)
        
        for section in sections:
            if not section:
                continue
            
            title = section.get("title", "Unknown")
            lines.append(f"\n{'=' * 70}")
            lines.append(title)
            lines.append(f"{'=' * 70}\n")
        
        # Add indicators summary
        if self.indicators_dict:
            lines.append("\n" + "=" * 70)
            lines.append("String Indicators")
            lines.append("=" * 70)
            
            ascii_strings = self.indicators_dict.get("ascii") or []
            unicode_strings = self.indicators_dict.get("unicode") or []
            
            if ascii_strings:
                lines.append(f"ASCII strings: {len(ascii_strings)} (first 10 shown)")
                for s in ascii_strings[:10]:
                    lines.append(f"  - {s}")
            
            if unicode_strings:
                lines.append(f"\nUnicode strings: {len(unicode_strings)} (first 10 shown)")
                for s in unicode_strings[:10]:
                    lines.append(f"  - {s}")
        
        return "\n".join(str(line) for line in lines)
