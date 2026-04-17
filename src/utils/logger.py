"""
Unified logging configuration for PE Analyzer.

Provides consistent logging across all modules with proper error tracking.
Combines module-level logger instance with root logger setup capabilities.
"""

import logging
import sys
import os
from pathlib import Path
from typing import Optional

# Add parent directory to path to import config
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../../'))
from config.logger_config import LOGGING_CONFIG

# Module-level logger instance
_logger: Optional[logging.Logger] = None

# Create logs directory if it doesn't exist
LOGS_DIR = Path(__file__).parent.parent.parent / "logs"
LOGS_DIR.mkdir(exist_ok=True)

# Define logger format
LOG_FORMAT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
DATE_FORMAT = '%Y-%m-%d %H:%M:%S'


def init_logger(name: str = None, level: str = None) -> logging.Logger:
    """
    Initialize and configure the logger.
    
    Args:
        name: Logger name (default from config)
        level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL) (default from config)
        
    Returns:
        Configured logger instance
    """
    global _logger
    
    # Use defaults if not provided
    if name is None:
        name = LOGGING_CONFIG['default_logger_name']
    if level is None:
        level = LOGGING_CONFIG['default_level']
    
    # Create logger
    _logger = logging.getLogger(name)
    _logger.setLevel(getattr(logging, level.upper(), logging.INFO))
    
    # Remove existing handlers to avoid duplicates
    _logger.handlers.clear()
    
    # Console handler with formatting
    console_handler = logging.StreamHandler(sys.stderr)
    console_handler.setLevel(getattr(logging, level.upper(), logging.INFO))
    
    formatter = logging.Formatter(
        '[%(levelname)s] %(name)s: %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    console_handler.setFormatter(formatter)
    _logger.addHandler(console_handler)
    
    return _logger


def get_logger(module_name: str = None) -> logging.Logger:
    """
    Get logger instance for specific module or the global logger.
    
    Args:
        module_name: Name of module (typically __name__), or None for global logger
        
    Returns:
        logging.Logger instance
    """
    if module_name:
        return logging.getLogger(module_name)
    
    global _logger
    if _logger is None:
        init_logger()
    return _logger

