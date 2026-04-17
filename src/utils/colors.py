"""
Rich markup color constants for consistent terminal output formatting.

This module centralizes all Rich color markup used throughout the application,
making it easy to maintain a consistent color scheme and modify colors globally.

Usage:
    from src.utils.colors import C
    output_console.print(f"{C.HEADER_CYAN}Section Title{C.END}")
    output_console.print(f"{C.SUCCESS}Analysis complete{C.END}")
"""

class C:
    """Color constants using Rich markup syntax."""
    
    # ==================== BASIC COLORS ====================
    RED = "[red]"
    YELLOW = "[yellow]"
    GREEN = "[green]"
    CYAN = "[cyan]"
    DIM = "[dim]"
    
    # ==================== BOLD VARIANTS ====================
    BOLD = "[bold]"
    BOLD_RED = "[bold red]"
    BOLD_YELLOW = "[bold yellow]"
    BOLD_CYAN = "[bold cyan]"
    BOLD_MAGENTA = "[bold magenta]"
    
    # ==================== CLOSING TAGS ====================
    END = "[/]"
    END_RED = "[/red]"
    END_YELLOW = "[/yellow]"
    END_GREEN = "[/green]"
    END_CYAN = "[/cyan]"
    END_DIM = "[/dim]"
    END_BOLD_RED = "[/bold red]"
    END_BOLD_YELLOW = "[/bold yellow]"
    END_BOLD_CYAN = "[/bold cyan]"
    END_BOLD_MAGENTA = "[/bold magenta]"
    
    # ==================== SEMANTIC COLORS ====================
    # Headers and sections
    HEADER = BOLD_CYAN
    HEADER_END = END_BOLD_CYAN
    
    # Status messages
    SUCCESS = GREEN
    SUCCESS_END = END_GREEN
    
    WARNING = YELLOW
    WARNING_END = END_YELLOW
    
    ERROR = RED
    ERROR_END = END_RED
    
    # Risk levels
    CRITICAL_LEVEL = BOLD_RED
    CRITICAL_LEVEL_END = END_BOLD_RED
    
    HIGH_LEVEL = RED
    HIGH_LEVEL_END = END_RED
    
    MEDIUM_LEVEL = YELLOW
    MEDIUM_LEVEL_END = END_YELLOW
    
    LOW_LEVEL = YELLOW
    LOW_LEVEL_END = END_YELLOW
    
    MINIMAL_LEVEL = GREEN
    MINIMAL_LEVEL_END = END_GREEN
    
    # Labels and field names
    LABEL = YELLOW
    LABEL_END = END_YELLOW
    
    # Severity indicators (for findings)
    SEVERITY_CRITICAL = BOLD_RED
    SEVERITY_CRITICAL_END = END_BOLD_RED
    
    SEVERITY_HIGH = BOLD_YELLOW
    SEVERITY_HIGH_END = END_BOLD_YELLOW
    
    SEVERITY_MEDIUM = BOLD_CYAN
    SEVERITY_MEDIUM_END = END_BOLD_CYAN
    
    # Dimmed/secondary text
    SECONDARY = DIM
    SECONDARY_END = END_DIM
    
    # Accents
    ACCENT = BOLD_MAGENTA
    ACCENT_END = END_BOLD_MAGENTA
