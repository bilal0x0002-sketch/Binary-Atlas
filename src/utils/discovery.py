"""
File discovery and batch processing utilities.
"""

import os
import glob
from typing import List


def discover_files(args) -> List[str]:
    """
    Discover files to analyze based on CLI arguments.
    
    Returns sorted list of file paths.
    """
    files = []
    
    if args.file:
        files = [args.file]
    elif args.directory:
        pe_extensions = ('*.exe', '*.dll', '*.sys', '*.EXE', '*.DLL', '*.SYS')
        files = sorted(set(
            file for ext in pe_extensions 
            for file in glob.glob(os.path.join(args.directory, '**', ext), recursive=True)
        ))
    elif args.glob:
        files = sorted(glob.glob(args.glob, recursive=True))
    
    return files
