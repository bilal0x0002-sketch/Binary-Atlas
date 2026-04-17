"""
Shared utilities for report formatting.

Common functions used across multiple formatters:
- HTML escaping and safety
- Rich markup stripping
- ANSI code removal
"""

import re
from typing import List


def strip_rich_markup(text: str) -> str:
    """Remove Rich library markup tags like [bold red], [/bold red], etc."""
    if not text:
        return text
    return re.sub(r'\[/?[^\]]*\]', '', text)


def strip_ansi_codes(text: str) -> str:
    """Remove ANSI escape codes for clean console output."""
    if not text:
        return text
    ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
    return ansi_escape.sub('', text)


def escape_html(text: str) -> str:
    """Escape HTML special characters."""
    if not text:
        return text
    return (text
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;")
            .replace("'", "&#39;"))


